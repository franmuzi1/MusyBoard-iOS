# MusyBoard-iOS

La cifratura end-to-end di [MusyBoard](https://github.com/franmuzi1/tastieraNoCC-app)
su iPhone, senza scrivere un'app iOS.

Su iOS una tastiera di sistema non puo' fare quello che fa su Android, e
pubblicare sull'App Store non e' una strada percorribile per questo progetto.
La via scelta e' diversa: **lo stesso identico core Rust**, compilato in
WebAssembly, eseguito dentro [Scriptable](https://scriptable.app/) — che e' un
motore JavaScript offline — e pilotato da due Comandi Rapidi.

Stesso core vuol dire stesso formato sul filo: un iPhone e un Android si
scrivono senza sapere l'uno dell'altro.

## Cosa c'e' dentro

| | |
|---|---|
| `src/` | il crate `musyboard-wasm`: 30 funzioni `mb_*` esportate, niente wasm-bindgen — marshalling a mano con puntatori e lunghezze a 32 bit |
| `scriptable/MusyBoard.js` | ~2100 righe: interfaccia, archiviazione, ponte con il wasm, UTF-8/Base64 e generatore di QR scritti a mano |
| `scriptable/INSTALLAZIONE.md` | i due Comandi Rapidi e la verifica end-to-end |
| `poc/` | la prova di fattibilita' della Fase 0, tenuta perche' documenta cosa e' stato verificato su un iPhone vero |

## Dipende dal core

`Cargo.toml` punta a `../tastieraNoCC` — il repo del core. Serve affiancato:

    ProgettiClaudeCode/
      tastieraNoCC/      il core
      MusyBoard-iOS/     questo

Non e' una copia del core: e' lo stesso codice, e una correzione crittografica
fatta li' arriva qui ricompilando.

**Il rovescio della medaglia, gia' successo una volta.** Il ponte Android vive
nello stesso repo del core, quindi un cambiamento che lo riguarda lo aggiorna
insieme. Questo no. Quando al core e' stata aggiunta una variante di `Error`,
`jni/` e' stato adeguato nello stesso commit e qui e' rimasto un `match` non
esaustivo — cioe' **questo crate ha smesso di compilare**, e nessuno se ne e'
accorto finche' non lo si e' ricostruito.

Non e' un difetto della separazione, e' il suo costo. Chi tocca `Error`,
`format.rs` o le firme pubbliche del core deve ricostruire anche qui: il
compilatore lo dice subito, ma solo a chi glielo chiede.

## Comandi

```
cargo test                                        # 14 test, su host
cargo clippy --all-targets -- -D warnings
cargo build --release --target wasm32-unknown-unknown
```

Il binario esce in `target/wasm32-unknown-unknown/release/musyboard_wasm.wasm`,
e una copia pronta da trasferire sull'iPhone sta in `dist/` (vedi
`dist/LEGGIMI.md`: e' una copia deliberata, non si aggiorna da sola).

Pesa ~289 KB e ha **zero import**: non chiede niente all'host, quindi
`WebAssembly.instantiate(bytes, {})` basta.

## La chiave privata sta in chiaro nel file, e va saputo

Su Android il segreto d'identita' e' avvolto da Android Keystore — `StrongBox`
dove c'e', `setUnlockedDeviceRequired`, in una cartella esclusa dai backup — e
quel che finisce su disco e' inservibile fuori da quel telefono.

Qui no. Sta in `config.json`, in Base64, in chiaro:

```json
{ "my_identity": { "secret_b64": "..." } }
```

**Cosa protegge comunque:** il file vive nella sandbox di Scriptable, quindi
nessun'altra app lo legge; e' in `FileManager.local()`, quindi **non**
sincronizza con iCloud Drive; e iOS lo cifra a riposo con il codice del
dispositivo, quindi un iPhone spento e bloccato non lo consegna.

**Cosa non protegge, ed e' la differenza che conta:** un **backup del
dispositivo** — iCloud o computer — contiene la chiave privata cosi' com'e'.
Su Android lo stesso backup conterrebbe un blob che senza quel telefono non
apre niente. Chi ottiene un backup di un iPhone ottiene l'identita'.

Non e' aggirabile da qui: Scriptable non espone nessun modo per escludere un
file dai backup, e non c'e' un equivalente del Keystore accessibile da uno
script. Si potrebbe cifrare `config.json` con una passphrase — il crate ha gia'
Argon2id per i backup — ma significherebbe chiederla a ogni uso, ed e' una
scelta di prodotto, non una svista da correggere di nascosto.

Finche' resta cosi': **un iPhone vale quanto il suo backup.**

## Stato

Tutto costruito e verificato **senza un iPhone**: test Rust sul target host,
vettori KAT incrociati fra Rust e JavaScript eseguiti sotto QuickJS,
corrispondenza uno a uno fra le funzioni chiamate da JS e quelle esportate dal
binario, e il generatore di QR confrontato contro una libreria di riferimento —
dove sono saltati fuori quattro difetti veri che a leggere il codice non si
vedevano.

Manca il passo che senza un device non si puo' fare: la prova end-to-end vera.
I passaggi sono in ordine in `scriptable/INSTALLAZIONE.md`.
