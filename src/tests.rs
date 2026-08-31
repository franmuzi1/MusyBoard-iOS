//! Test del crate wasm.
//!
//! **Cosa NON copre questo file, e perche'.** Le funzioni `#[no_mangle]
//! extern "C"` in `lib.rs` impacchettano puntatori a 32 bit (`u32`) — corretto
//! per `wasm32-unknown-unknown`, dove i puntatori SONO a 32 bit, ma non
//! testabile su un host a 64 bit: un indirizzo reale non ci sta in un `u32`
//! senza troncarsi. Questi test quindi non passano MAI dalla firma `extern
//! "C"`: chiamano `Session`/`IosKeyring` direttamente (Rust sicuro, nessun
//! puntatore grezzo), che e' esattamente il codice che quelle funzioni
//! avvolgono. Coprono cosi' tutta la logica — flusso identita'/contatti,
//! cifratura/decifratura, rogo, idratazione del keyring, layout binario di
//! `codec` — tranne il sottile strato di marshalling puntatore↔byte, che resta
//! da verificare sul target reale (Fase 0/2 del piano: gia' confermato che
//! `WebAssembly.instantiate` e le chiamate a interi funzionano dentro
//! Scriptable).

use super::*;
use codec::{
    decode_peer_record, decode_prekey_record, encode_incoming_file, encode_incoming_item,
    encode_peer_record, encode_prekey_record, TAG_BURNED, TAG_IDENTITY_CARD, TAG_MESSAGE,
    TAG_OWN_IDENTITY_CARD, TAG_OWN_MESSAGE,
};
use keyboard_cipher_core::api::{IncomingItem, SenderStatus};
use keyboard_cipher_core::keys::{PeerRecord, PinOutcome, PrekeyRecord};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroizing;

const ORA: i64 = 1_000_000;

fn rng_di_prova(seme: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seme; 32])
}

fn identita_di_prova(seme: u8) -> Identity {
    Identity::from_secret_bytes([seme; 32]).expect("32 byte sono sempre validi per X25519")
}

fn chiave(seme: u8) -> PublicKey {
    PublicKey::from_bytes([seme; 32])
}

// ---------------------------------------------------------------------------
// RNG: deve richiedere un seme nuovo a ogni operazione
// ---------------------------------------------------------------------------

#[test]
fn seme_si_consuma_e_non_si_riusa() {
    rng::seed([7u8; 32]);
    assert!(rng::take().is_some());
    // Senza un nuovo seed, la seconda `take` non deve restituire nulla: e'
    // la garanzia che impedisce di riusare un seme fra due operazioni.
    assert!(rng::take().is_none());
}

// ---------------------------------------------------------------------------
// codec: round-trip dei record persistiti
// ---------------------------------------------------------------------------

#[test]
fn peer_record_con_etichetta_va_e_torna() {
    let record = PeerRecord {
        public: chiave(1),
        label: Some("Marco 🙂".to_owned()),
        first_seen_unix: ORA,
        verified: true,
    };
    let bytes = encode_peer_record(&record);
    let tornato = decode_peer_record(&bytes).expect("deve decodificare cio' che ha appena codificato");
    assert_eq!(tornato, record);
}

#[test]
fn peer_record_senza_etichetta_va_e_torna() {
    let record = PeerRecord {
        public: chiave(2),
        label: None,
        first_seen_unix: -42,
        verified: false,
    };
    let bytes = encode_peer_record(&record);
    let tornato = decode_peer_record(&bytes).expect("round-trip");
    assert_eq!(tornato, record);
}

#[test]
fn peer_record_troncato_non_decodifica_e_non_va_in_panic() {
    let record = PeerRecord {
        public: chiave(3),
        label: Some("qualcosa".to_owned()),
        first_seen_unix: ORA,
        verified: true,
    };
    let bytes = encode_peer_record(&record);
    for taglio in 0..bytes.len() {
        let corto = bytes.get(..taglio).unwrap_or(&[]);
        // Non deve panicare qualunque sia il taglio: o decodifica (non deve,
        // essendo troncato) o torna `None`.
        assert!(decode_peer_record(corto).is_none() || taglio == bytes.len());
    }
}

#[test]
fn prekey_record_pieno_va_e_torna() {
    let mie: Vec<Zeroizing<[u8; 32]>> = (10u8..15).map(|n| Zeroizing::new([n; 32])).collect();
    let record = PrekeyRecord {
        peer: chiave(4),
        sua_prekey: Some(chiave(50)),
        mie,
        mia_epoca: Some(Zeroizing::new([60u8; 32])),
        sua_epoca: Some(chiave(70)),
        visto_a: 111,
        rogo_a: 222,
    };
    let bytes = encode_prekey_record(&record);
    let tornato = decode_prekey_record(&bytes).expect("round-trip");
    assert_eq!(tornato.peer, record.peer);
    assert_eq!(tornato.sua_prekey, record.sua_prekey);
    assert_eq!(
        tornato.mie.iter().map(|k| **k).collect::<Vec<_>>(),
        record.mie.iter().map(|k| **k).collect::<Vec<_>>()
    );
    assert_eq!(tornato.mia_epoca.map(|k| *k), record.mia_epoca.map(|k| *k));
    assert_eq!(tornato.sua_epoca, record.sua_epoca);
    assert_eq!(tornato.visto_a, record.visto_a);
    assert_eq!(tornato.rogo_a, record.rogo_a);
}

#[test]
fn prekey_record_vuoto_va_e_torna() {
    let record = PrekeyRecord {
        peer: chiave(5),
        sua_prekey: None,
        mie: Vec::new(),
        mia_epoca: None,
        sua_epoca: None,
        visto_a: i64::MIN,
        rogo_a: i64::MIN,
    };
    let bytes = encode_prekey_record(&record);
    let tornato = decode_prekey_record(&bytes).expect("round-trip");
    assert_eq!(tornato.peer, record.peer);
    assert!(tornato.sua_prekey.is_none());
    assert!(tornato.mie.is_empty());
    assert!(tornato.mia_epoca.is_none());
    assert!(tornato.sua_epoca.is_none());
}

// ---------------------------------------------------------------------------
// IosKeyring: idratazione (dump -> restore su un keyring nuovo)
// ---------------------------------------------------------------------------

#[test]
fn keyring_sopravvive_al_giro_dump_restore() {
    let mut originale = IosKeyring::default();
    originale.restore_peer(PeerRecord {
        public: chiave(1),
        label: Some("Ada".to_owned()),
        first_seen_unix: ORA,
        verified: true,
    });
    originale.restore_prekey(PrekeyRecord {
        peer: chiave(1),
        sua_prekey: Some(chiave(9)),
        mie: vec![Zeroizing::new([11u8; 32]), Zeroizing::new([12u8; 32])],
        mia_epoca: Some(Zeroizing::new([13u8; 32])),
        sua_epoca: Some(chiave(14)),
        visto_a: 5,
        rogo_a: i64::MIN,
    });

    let mut ricostruito = IosKeyring::default();
    for record in originale.peer_records() {
        ricostruito.restore_peer(record.clone());
    }
    for record in originale.prekey_dump() {
        ricostruito.restore_prekey(record);
    }

    assert_eq!(ricostruito.peer_records(), originale.peer_records());
    let originale_dump = originale.prekey_dump();
    let ricostruito_dump = ricostruito.prekey_dump();
    assert_eq!(originale_dump.len(), 1);
    assert_eq!(ricostruito_dump.len(), 1);
    let (o, r) = (
        originale_dump.first().expect("un solo record"),
        ricostruito_dump.first().expect("un solo record"),
    );
    assert_eq!(o.peer, r.peer);
    assert_eq!(o.sua_prekey, r.sua_prekey);
    assert_eq!(o.sua_epoca, r.sua_epoca);
    assert_eq!(o.visto_a, r.visto_a);
}

// ---------------------------------------------------------------------------
// Flusso completo: due identita', scambio di presentazioni, andata e
// ritorno di un messaggio, rogo. Tutto attraverso `Session` direttamente —
// e' il codice che le funzioni `extern "C"` di lib.rs avvolgono.
// ---------------------------------------------------------------------------

#[test]
fn conversazione_completa_fra_due_identita() {
    let alice_id = identita_di_prova(1);
    let bob_id = identita_di_prova(2);
    let alice_pub = alice_id.public();
    let bob_pub = bob_id.public();

    let mut alice = Session::new(alice_id, IosKeyring::default());
    let mut bob = Session::new(bob_id, IosKeyring::default());

    // Alice si presenta, Bob importa la card.
    let card_alice = alice.identity_card(&mut rng_di_prova(10));
    let esito = bob
        .handle_incoming_text(APP, &card_alice, ORA)
        .expect("una identity card valida deve aprirsi");
    match esito {
        IncomingItem::IdentityCard {
            peer,
            outcome,
            fingerprint,
        } => {
            assert_eq!(peer, alice_pub);
            assert_eq!(outcome, PinOutcome::Pinned);
            assert_eq!(fingerprint, keyboard_cipher_core::keys::Fingerprint::of(&alice_pub));
        }
        IncomingItem::Message(_) => panic!("atteso IdentityCard, arrivato Message"),
        IncomingItem::OwnMessage { .. } => panic!("atteso IdentityCard, arrivato OwnMessage"),
        IncomingItem::Burned { .. } => panic!("atteso IdentityCard, arrivato Burned"),
        IncomingItem::OwnIdentityCard { .. } => panic!("atteso IdentityCard, arrivato OwnIdentityCard"),
    }
    bob.set_current_peer(APP, &alice_pub)
        .expect("alice e' appena stata fissata");

    // Stesso scambio nell'altra direzione.
    let card_bob = bob.identity_card(&mut rng_di_prova(20));
    alice
        .handle_incoming_text(APP, &card_bob, ORA)
        .expect("card di bob valida");
    alice
        .set_current_peer(APP, &bob_pub)
        .expect("bob e' appena stato fissato");

    // Bob scrive per primo.
    let blob = bob
        .encrypt_for_app_with(APP, b"ciao alice", ORA, &mut rng_di_prova(30), false)
        .expect("cifratura verso un contatto fissato non deve fallire");

    let ricevuto = alice
        .handle_incoming_text(APP, &blob, ORA + 1)
        .expect("il blob di bob deve aprirsi per alice");
    let IncomingItem::Message(msg) = ricevuto else {
        panic!("atteso un messaggio")
    };
    assert_eq!(msg.sender, bob_pub);
    assert_eq!(msg.plaintext.as_bytes(), b"ciao alice");
    assert!(!msg.gruppo);
    // Bob era gia' stato fissato importando la sua card: lo status deve
    // essere Known, non New (che direbbe "mittente mai visto" a torto).
    match &msg.sender_status {
        SenderStatus::Known { verified, .. } => assert!(!verified),
        SenderStatus::New => panic!("bob era gia' fissato, non dovrebbe risultare New"),
    }
    // Il codec deve poter incapsulare questo esito reale senza panicare, e i
    // byte devono contenere il tag giusto: e' l'unica cosa che i test possono
    // verificare senza un decodificatore JS a fianco.
    let incapsulato = encode_incoming_item(&IncomingItem::Message(msg));
    assert_eq!(incapsulato.first().copied(), Some(TAG_MESSAGE));

    // Leggere ha fissato il destinatario corrente per alice: puo' rispondere
    // senza un `set_current_peer` esplicito, esattamente come nella decisione
    // "leggere sceglie con chi si sta parlando".
    let risposta = alice
        .encrypt_for_app_with(APP, b"ciao bob", ORA + 2, &mut rng_di_prova(40), false)
        .expect("alice ha gia' un destinatario corrente dopo la lettura");
    let ricevuta_da_bob = bob
        .handle_incoming_text(APP, &risposta, ORA + 3)
        .expect("la risposta di alice deve aprirsi per bob");
    let IncomingItem::Message(msg2) = ricevuta_da_bob else {
        panic!("atteso un messaggio")
    };
    assert_eq!(msg2.plaintext.as_bytes(), b"ciao bob");

    // Rogo: bob distrugge la conversazione con alice.
    let richiesta_rogo = bob
        .burn_conversation(&alice_pub, ORA + 4, &mut rng_di_prova(50))
        .expect("bob ha alice fra i contatti");
    let esito_rogo = alice
        .handle_incoming_text(APP, &richiesta_rogo, ORA + 5)
        .expect("la richiesta di rogo deve aprirsi per alice");
    match esito_rogo {
        IncomingItem::Burned { peer, .. } => assert_eq!(peer, bob_pub),
        IncomingItem::Message(_) => panic!("atteso Burned, arrivato Message"),
        IncomingItem::OwnMessage { .. } => panic!("atteso Burned, arrivato OwnMessage"),
        IncomingItem::OwnIdentityCard { .. } => panic!("atteso Burned, arrivato OwnIdentityCard"),
        IncomingItem::IdentityCard { .. } => panic!("atteso Burned, arrivato IdentityCard"),
    }
}

#[test]
fn messaggio_di_gruppo_si_apre_per_ogni_destinatario() {
    let alice_id = identita_di_prova(1);
    let bob_id = identita_di_prova(2);
    let carol_id = identita_di_prova(3);
    let mut alice = Session::new(alice_id, IosKeyring::default());
    let mut bob = Session::new(bob_id, IosKeyring::default());
    let mut carol = Session::new(carol_id, IosKeyring::default());
    let bob_pub = bob.identity().public();
    let carol_pub = carol.identity().public();

    // Alice deve avere Bob e Carol fissati per poter cifrare per loro.
    let card_bob = bob.identity_card(&mut rng_di_prova(10));
    alice.handle_incoming_text(APP, &card_bob, ORA).unwrap();
    let card_carol = carol.identity_card(&mut rng_di_prova(11));
    alice.handle_incoming_text(APP, &card_carol, ORA).unwrap();
    // E Bob/Carol devono conoscere Alice per riconoscerla come mittente
    // (i messaggi di gruppo hanno mittente effimero: si prova sui contatti
    // gia' fissati).
    let card_alice = alice.identity_card(&mut rng_di_prova(12));
    bob.handle_incoming_text(APP, &card_alice, ORA).unwrap();
    carol.handle_incoming_text(APP, &card_alice, ORA).unwrap();

    let blob = alice
        .encrypt_group(
            &[bob_pub.clone(), carol_pub.clone()],
            b"ciao a entrambi",
            ORA,
            &mut rng_di_prova(20),
        )
        .expect("bob e carol sono fissati, deve cifrarsi");

    for destinatario in [&mut bob, &mut carol] {
        let esito = destinatario
            .handle_incoming_text(APP, &blob, ORA + 1)
            .expect("il gruppo deve aprirsi per ogni destinatario");
        let IncomingItem::Message(msg) = esito else {
            panic!("atteso un messaggio")
        };
        assert!(msg.gruppo);
        // 3 slot: bob, carol, e quello del mittente (K2 — "il mittente ha
        // uno slot suo, ed e' il nono" nel caso a 8 destinatari; qui sono 2+1=3).
        assert_eq!(msg.destinatari, 3);
        assert_eq!(msg.plaintext.as_bytes(), b"ciao a entrambi");
    }
}

#[test]
fn allegato_va_e_torna_con_forward_secrecy() {
    let alice_id = identita_di_prova(1);
    let bob_id = identita_di_prova(2);
    let mut alice = Session::new(alice_id, IosKeyring::default());
    let mut bob = Session::new(bob_id, IosKeyring::default());
    let alice_pub = alice.identity().public();
    let bob_pub = bob.identity().public();

    // Si fissano a vicenda scambiandosi le card, come nel flusso normale —
    // encrypt_file_with richiede il peer gia' nel keyring.
    let card_alice = alice.identity_card(&mut rng_di_prova(10));
    bob.handle_incoming_text(APP, &card_alice, ORA).unwrap();
    let card_bob = bob.identity_card(&mut rng_di_prova(20));
    alice.handle_incoming_text(APP, &card_bob, ORA).unwrap();

    let meta = keyboard_cipher_core::file::FileMeta {
        name: "vacanza.jpg".to_owned(),
        mime: "image/jpeg".to_owned(),
    };
    let contenuto = vec![0xABu8; 200];
    let blob = alice
        .encrypt_file_with(&bob_pub, &meta, &contenuto, ORA, &mut rng_di_prova(30), true)
        .expect("bob e' fissato, l'allegato deve cifrarsi");

    let ricevuto = bob
        .handle_incoming_file(&blob, ORA + 1)
        .expect("l'allegato di alice deve aprirsi per bob");
    assert_eq!(ricevuto.sender, alice_pub);
    assert!(!ricevuto.nostro);
    assert_eq!(ricevuto.file.meta.name, "vacanza.jpg");
    assert_eq!(ricevuto.file.meta.mime, "image/jpeg");
    assert_eq!(ricevuto.file.content.as_slice(), contenuto.as_slice());

    // La codifica verso JS deve almeno iniziare con la chiave del mittente:
    // e' il primo campo del layout (vedi `codec::encode_incoming_file`).
    let incapsulato = encode_incoming_file(&ricevuto);
    assert_eq!(incapsulato.get(..32), Some(alice_pub.as_bytes().as_slice()));
}

#[test]
fn backup_andata_e_ritorno_con_portachiavi_opaco() {
    let alice_id = identita_di_prova(1);
    let keyring_finto = b"non importa cosa ci sia qui dentro, backup::export lo tratta come byte opachi";
    let blob = keyboard_cipher_core::backup::export(
        &alice_id,
        keyring_finto,
        b"una passphrase",
        &mut rng_di_prova(80),
    )
    .expect("export non deve fallire con una passphrase non vuota");

    let aperto = keyboard_cipher_core::backup::import(&blob, b"una passphrase")
        .expect("deve riaprirsi con la stessa passphrase");
    assert_eq!(aperto.secret.as_ref(), &[1u8; 32]);
    assert_eq!(aperto.keyring.as_slice(), keyring_finto);

    // Passphrase sbagliata: stesso errore opaco di sempre, non distinguibile
    // da un file manomesso.
    let fallito = keyboard_cipher_core::backup::import(&blob, b"sbagliata");
    assert!(fallito.is_err());
}

#[test]
fn dimenticare_un_contatto_toglie_anche_il_destinatario_corrente() {
    let alice_id = identita_di_prova(1);
    let bob_id = identita_di_prova(2);
    let mut alice = Session::new(alice_id, IosKeyring::default());
    let bob = Session::new(bob_id, IosKeyring::default());
    let bob_pub = bob.identity().public();

    let card_bob = bob.identity_card(&mut rng_di_prova(70));
    alice
        .handle_incoming_text(APP, &card_bob, ORA)
        .expect("card di bob valida, lo fissa");
    alice
        .set_current_peer(APP, &bob_pub)
        .expect("bob e' fissato, puo' diventare destinatario corrente");
    assert_eq!(alice.current_peer(APP), Some(&bob_pub));

    let c_era = alice
        .forget_peer(&bob_pub)
        .expect("forget non fallisce su un peer fissato");
    assert!(c_era);
    // La parte che conta di piu': dimenticare toglie ANCHE il destinatario
    // corrente, non solo il pin — altrimenti si continuerebbe a cifrare
    // verso una chiave non piu' fissata (`src/api.rs:1171-1181`).
    assert_eq!(alice.current_peer(APP), None);

    let di_nuovo = alice
        .forget_peer(&bob_pub)
        .expect("forget su un peer assente non fallisce");
    assert!(!di_nuovo);
}

#[test]
fn own_identity_card_e_own_message_si_riconoscono() {
    let alice_id = identita_di_prova(1);
    let mut alice = Session::new(alice_id, IosKeyring::default());

    // La propria card, riaperta: non si fissa niente.
    let propria_card = alice.identity_card(&mut rng_di_prova(60));
    let esito = alice
        .handle_incoming_text(APP, &propria_card, ORA)
        .expect("la propria card deve riaprirsi");
    match &esito {
        IncomingItem::OwnIdentityCard { .. } => {}
        IncomingItem::Message(_) => panic!("atteso OwnIdentityCard, arrivato Message"),
        IncomingItem::OwnMessage { .. } => panic!("atteso OwnIdentityCard, arrivato OwnMessage"),
        IncomingItem::Burned { .. } => panic!("atteso OwnIdentityCard, arrivato Burned"),
        IncomingItem::IdentityCard { .. } => panic!("atteso OwnIdentityCard, arrivato IdentityCard"),
    }
    let incapsulato = encode_incoming_item(&esito);
    assert_eq!(incapsulato.first().copied(), Some(TAG_OWN_IDENTITY_CARD));
}

#[test]
fn tag_burned_e_own_message_hanno_i_valori_dichiarati() {
    // Verifica statica dei tag: se qualcuno li cambia per sbaglio, un lettore
    // JS gia' scritto smette di riconoscerli senza che nessun test se ne
    // accorga altrove.
    assert_eq!(TAG_MESSAGE, 0);
    assert_eq!(TAG_OWN_MESSAGE, 1);
    assert_eq!(TAG_BURNED, 2);
    assert_eq!(TAG_OWN_IDENTITY_CARD, 3);
    assert_eq!(TAG_IDENTITY_CARD, 4);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// **KAT cross-linguaggio.** Non verifica nulla da sola (non c'e' un
/// interprete JS in questa suite Rust): stampa vettori esadecimali che il
/// test JS gemello (`wasm/scriptable/test-codec.js`) porta come costanti
/// congelate. Se questo output cambia, quel file va rigenerato — stesso
/// principio dei KAT del core (`CLAUDE.md`, sezione Test): un formato senza
/// vettore puo' muoversi in silenzio, e in silenzio vuol dire che se ne
/// accorge l'utente mesi dopo da un messaggio che non si apre.
///
/// Esegui con `cargo test kat_vettori_per_js -- --nocapture --ignored`.
#[test]
#[ignore = "stampa vettori a mano, non un'asserzione automatica"]
fn kat_vettori_per_js() {
    let con_etichetta = PeerRecord {
        public: chiave(1),
        label: Some("Marco".to_owned()),
        first_seen_unix: 1_700_000_000,
        verified: true,
    };
    println!("PEER_CON_ETICHETTA = {}", hex(&encode_peer_record(&con_etichetta)));

    let senza_etichetta = PeerRecord {
        public: chiave(2),
        label: None,
        first_seen_unix: -1,
        verified: false,
    };
    println!("PEER_SENZA_ETICHETTA = {}", hex(&encode_peer_record(&senza_etichetta)));

    let prekey_pieno = PrekeyRecord {
        peer: chiave(3),
        sua_prekey: Some(chiave(50)),
        mie: vec![Zeroizing::new([11u8; 32]), Zeroizing::new([12u8; 32])],
        mia_epoca: Some(Zeroizing::new([60u8; 32])),
        sua_epoca: Some(chiave(70)),
        visto_a: 111,
        rogo_a: -1,
    };
    println!("PREKEY_PIENO = {}", hex(&encode_prekey_record(&prekey_pieno)));

    let prekey_vuoto = PrekeyRecord {
        peer: chiave(4),
        sua_prekey: None,
        mie: Vec::new(),
        mia_epoca: None,
        sua_epoca: None,
        visto_a: i64::MIN,
        rogo_a: i64::MIN,
    };
    println!("PREKEY_VUOTO = {}", hex(&encode_prekey_record(&prekey_vuoto)));

    // Un IncomingItem::Message reale, da uno scambio vero e deterministico.
    let alice_id = identita_di_prova(1);
    let bob_id = identita_di_prova(2);
    let mut alice = Session::new(alice_id, IosKeyring::default());
    let mut bob = Session::new(bob_id, IosKeyring::default());
    let card_alice = alice.identity_card(&mut rng_di_prova(10));
    bob.handle_incoming_text(APP, &card_alice, ORA).unwrap();
    bob.set_current_peer(APP, &alice.identity().public()).unwrap();
    let card_bob = bob.identity_card(&mut rng_di_prova(20));
    alice.handle_incoming_text(APP, &card_bob, ORA).unwrap();
    alice.set_current_peer(APP, &bob.identity().public()).unwrap();
    let blob = bob
        .encrypt_for_app_with(APP, "ciao mondo".as_bytes(), ORA, &mut rng_di_prova(30), false)
        .unwrap();
    let msg = alice.handle_incoming_text(APP, &blob, ORA + 1).unwrap();
    println!("INCOMING_MESSAGE = {}", hex(&encode_incoming_item(&msg)));

    let propria_card = alice.identity_card(&mut rng_di_prova(60));
    let own_card = alice.handle_incoming_text(APP, &propria_card, ORA).unwrap();
    println!("OWN_IDENTITY_CARD = {}", hex(&encode_incoming_item(&own_card)));
}

