# `musyboard_wasm.wasm`

Il binario da copiare sull'iPhone, versionato **di proposito** anche se e' un
artefatto di compilazione.

Il motivo e' pratico: chi installa deve poter prendere il file e basta, senza
una toolchain Rust e senza `wasm32-unknown-unknown` installato. Un progetto che
per essere provato da una persona qualunque richiede prima di compilarlo non
verra' provato.

Stava dentro `target/`, che e' in `.gitignore`: un `cargo clean` lo cancellava e
un `cargo build` non lo aggiornava qui. Ora sta fuori, ed e' una copia
deliberata — non si aggiorna da sola.

**Dopo ogni modifica al crate va rifatta**, altrimenti quello che si trasferisce
sull'iPhone non e' quello che dice il sorgente:

    cargo build --release --target wasm32-unknown-unknown
    cp target/wasm32-unknown-unknown/release/musyboard_wasm.wasm dist/

Per controllare che sia quello giusto — e che non abbia acquistato dipendenze
dall'host, che sarebbe la rottura silenziosa da temere — vale la proprieta'
verificata nella Fase 0: **zero import**. Se un giorno la sezione import
comparisse, `WebAssembly.instantiate(bytes, {})` con import vuoti smetterebbe di
bastare e il modulo non caricherebbe dentro Scriptable.
