// Test dei controlli sul seme di entropia — FUORI da Scriptable.
//
// Si carica come `test-codec.js`: prima MusyBoard.js, poi questo, nello stesso
// contesto JS. Vedi l'intestazione di quel file per il perche' funziona.
//
// Perche' questi controlli hanno un test tutto loro: il ponte di entropia e'
// l'unico pezzo del sistema che dipende dal comportamento di WKWebView, ed e'
// stato visto funzionare **una volta sola**, su un iPhone in prestito. Se si
// rompesse, si romperebbe in silenzio — e cifrare con entropia finta e' il
// guasto peggiore che questo progetto possa produrre.
//
// `controllaSeme` e' stata scritta sincrona e separata da `freshEntropy32`
// proprio per poter essere eseguita qui: dentro la funzione asincrona sarebbe
// stata soltanto rileggibile.

let ePassati = 0;
let eFalliti = 0;

function eCheck(nome, ok) {
  if (ok) {
    ePassati++;
  } else {
    eFalliti++;
    print("FALLITO: " + nome);
  }
}

function seme(f) {
  const a = [];
  for (let k = 0; k < 32; k++) a.push(f(k));
  return new Uint8Array(a);
}

function solleva(bytes) {
  try {
    controllaSeme(bytes);
    return false;
  } catch (e) {
    return true;
  }
}

print("--- controlli sul seme di entropia ---");

// Un seme plausibile passa. Senza questo, un controllo troppo severo
// bloccherebbe tutto e il test non se ne accorgerebbe.
ultimoSeme = null;
eCheck("un seme buono passa", !solleva(seme((k) => (k * 7 + 3) & 255)));

// Lunghezze sbagliate: il Rust le rifiuta gia', ma qui l'errore e' leggibile e
// arriva prima di allocare nella memoria del wasm.
ultimoSeme = null;
eCheck("zero byte", solleva(new Uint8Array(0)));
eCheck("16 byte", solleva(new Uint8Array(16)));
eCheck("33 byte", solleva(new Uint8Array(33)));

// Un ponte inceppato che risponde sempre la stessa cosa.
ultimoSeme = null;
eCheck("32 zeri", solleva(seme(() => 0)));
ultimoSeme = null;
eCheck("32 byte tutti uguali", solleva(seme(() => 0xab)));

// Il caso che conta davvero: una WebView che restituisce un valore in cache.
// Due operazioni con lo stesso seme = stessa effimera e stesso nonce = riuso
// di keystream.
const ripetuto = seme((k) => (k * 13 + 5) & 255);
ultimoSeme = null;
controllaSeme(ripetuto);
ultimoSeme = ripetuto;
eCheck("lo stesso seme due volte viene rifiutato", solleva(ripetuto));

// E un seme diverso dopo un altro passa: il controllo sopra non deve aver
// bloccato tutto per sempre.
eCheck("un seme diverso dal precedente passa", !solleva(seme((k) => (k * 29 + 11) & 255)));

print("");
print(ePassati + " passati, " + eFalliti + " falliti");
if (eFalliti > 0) {
  throw new Error(eFalliti + " test sull'entropia falliti");
}
