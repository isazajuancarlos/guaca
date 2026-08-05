# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Configuración general: `~/.claude/CLAUDE.md`** — reglas que no se rompen, las
> directivas numeradas y las máquinas montadas (hooks, permisos, skills). Se carga
> en toda sesión y **no se copia aquí**; este archivo lleva SOLO lo de guaca. El
> inventario está en `/mnt/data/conocimiento/MAPA.md`.
>
> **guaca se lleva desde SU carpeta**: `cd /mnt/data/guaca && claude`. Hasta este
> archivo era el último miembro de la «familia Quipu» que compartía el
> `CLAUDE.md` de decod; con el suyo propio sale igual que tunjo y que chuspa, y
> esa lista se queda vacía. Del `CLAUDE.md` de decod solo hace falta lo de «Quién
> consume Quipu» cuando se vaya a mover el requisito de `quipu`.

guaca es una **fachada delgada** de protección en reposo para aplicaciones, sobre
[Quipu](https://crates.io/crates/quipu). AGPL-3.0-or-later con licencia comercial
aparte (la política de Quipu, del cual es fachada). **Repositorio público.**

**No reimplementa criptografía.** Ese es el contrato del proyecto, no un detalle
de estilo: si un cambio aquí necesita escribir una primitiva, el cambio va en
Quipu. Lo que guaca aporta es la *decisión* —qué se ata a qué, qué se rechaza,
qué se hace con un dato roto—, que es exactamente lo que divergía cuando estaba
copiada en dos aplicaciones.

## Comandos

```bash
cargo test                      # 61 pruebas, ~31 s en debug (medido 2026-08-05)
cargo test freno::pruebas::ciento_veinte_intentos   # una sola, por ruta completa
cargo test freno::                                  # un módulo
cargo clippy --all-targets -- -D warnings           # EXACTAMENTE lo que corre el CI
cargo deny check                                    # cadena de suministro (deny.toml)
```

**De los ~29 s, 20 s son una sola prueba**: `auditoria::simulacion_de_manipulaciones`,
que sella 100 entradas y altera 16 posiciones, cada una con firma híbrida Ed25519
+ ML-DSA-87. En debug eso son decenas de ms por verificación y verificar una
cadena es O(n). Al iterar sobre otro módulo, filtra por nombre; no vale la pena
mover nada a `release` por esto.

**`Cargo.lock` SÍ se versiona desde el 2026-08-04**, y no por convención sino por
una ceguera medida: sin él, el grafo de dependencias de GitHub solo veía los
**10** crates nombrados en `Cargo.toml` de un árbol de **119**, así que las
alertas de Dependabot no alcanzaban ni una primitiva criptográfica —`ml-dsa`,
`ml-kem`, `curve25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `subtle`,
`getrandom`, `quipu-nucleo`…—. Una alarma que no ve el 92% del árbol da
«sin alertas» y «sin mirar» con la misma cara. Los cinco repositorios hermanos ya
lo versionaban; guaca era la excepción.

**No afecta a los consumidores**: cargo ignora el lock de una dependencia, así
que medico, informes y tunjo siguen resolviendo el suyo. Lo que fija la versión
de guaca en ellos es su `rev` de git, no este archivo.

El precio, para que no sorprenda: el CI pasa a probar un árbol **fijado** en vez
de «lo último compatible», así que ya no cazará solo que una versión nueva de una
dependencia rompa algo. Eso lo cubre el PR semanal agrupado de Dependabot, que es
exactamente una resolución fresca puesta a correr contra las pruebas.

## Los dos tipos de módulo

La distinción que hay que tener clara antes de tocar nada: **la mitad de `src/`
envuelve a Quipu y la otra mitad no lo toca**. Un cambio en Quipu solo puede
romper la primera.

| Módulo | Qué hace | Qué de Quipu usa |
|---|---|---|
| `reposo` | cifrado autenticado de archivos y blobs (Argon2 → AEAD → padding Padmé) | `api::encode_to_blob` / `decode_from_blob` |
| `firma` | integridad y no repudio post-cuánticos; `canonico()` = JSON con claves ordenadas | `api::encode_signed` / `decode_verified`, `pqsign` |
| `custodia` | derivar una clave de un secreto de despliegue y repartirla 2-de-3 | `kdf`, `shamir` (feature `escrow`), `aleatorio` |
| `auditoria` | bitácora encadenada por hash y firmada | solo a través de `crate::firma` |
| `freno` | la regla que frena el ensayo de contraseñas | **nada** |
| `sesion` | token HMAC firmado `id\|caducidad\|firma` | **nada** (`hmac` + `sha2`) |
| `claves` | contraseñas con Argon2 | **nada** (`argon2`) |

`lib.rs` no tiene más lógica que `dict()`, el alfabeto ASCII imprimible
(`0x21..=0x7e`) que Quipu usa por defecto. **Ese alfabeto entra en el fingerprint
del contenedor cifrado y en la verificación de firmas**: cambiarlo hace ilegible
todo lo ya guardado por cualquier consumidor. No es una constante de estilo.

## Lo que no puede cambiar sin romper datos ajenos

guaca produce artefactos que las aplicaciones **persisten**. Cuatro formatos son
compatibilidad hacia atrás, no decisiones reabiertas:

- **`dict()`** — ver arriba.
- **`firma::canonico`** — JSON con claves ordenadas y separadores compactos, el
  mismo esquema que `json.dumps(sort_keys=True, separators=(",",":"))`. Una firma
  hecha aquí verifica contra la rueda de Python de Quipu y al revés; tocar el
  serializador rompe esa equivalencia sin dar ningún error.
- **la codificación de la firma híbrida** (Ed25519 + ML-DSA-87) tal como la
  serializa `encode_signed` sobre `dict()`. No es código de guaca —vive en
  quipu— pero **el formato viaja en cada firma que un consumidor guarda**, así
  que romperlo aquí abajo hace que toda historia clínica y toda bitácora ya
  firmadas se lean como manipuladas. Lo ancla desde el 2026-08-05
  `firma::una_firma_de_2026_sigue_verificando`, con una firma emitida por
  **guaca `d786d1c` / quipu 0.10.0** y verificada por el binario de hoy.
- **`auditoria::preimagen`** — `{"cont": …, "prev": hex, "seq": n}`. Cambiarla
  invalida todas las cadenas ya selladas, que es precisamente lo que la cadena
  existe para hacer notar.
- **`sesion`** — el formato del token y el HMAC. Cambiarlos cierra la sesión de
  todo el mundo a la vez.

Ante cualquiera de los cuatro: versión nueva y migración explícita del
consumidor, nunca un cambio en sitio.

**Y desde el 2026-08-04 los cuatro tienen VECTOR FIJO, que es lo que convierte
esa frase en un mecanismo. Desde el 2026-08-05 son SEIS**: se le añadió el suyo
a `custodia::derivar`, de donde sale la clave maestra, y —el mismo día, más
tarde— a **`firma`**, que era el último módulo persistente sin ancla. Hasta ese
día la lista era prosa: todas las pruebas
codificaban y decodificaban con el mismo binario, así que medían el códec contra
sí mismo y habrían pasado en verde con el formato cambiado. Ahora cada una compara
contra un artefacto **capturado antes y pegado como literal** — un blob cifrado,
dos comparticiones, un hash de cadena, un token—. Comprobado rompiendo el formato
en el CÓDIGO MEDIDO, no en el arnés:

| Se rompió esto | Se puso roja |
|---|---|
| `dict()`: alfabeto `0x7e` → `0x7d` | `reposo::un_blob_de_2026_sigue_descifrando` (`CodebookMismatch`) |
| `auditoria::preimagen`: clave `"cont"` → `"contenido"` | `el_hash_de_una_entrada_de_2026_no_ha_cambiado` |
| `sesion::firmar`: un byte más en el HMAC | `un_token_de_2026_sigue_verificando` |
| `sesion::verificar`: separador `\|` → `.` | `un_token_de_2026_sigue_verificando` |
| `custodia::recuperar`: base64 url-safe → estándar | `una_comparticion_de_2026_sigue_recuperando` |
| `custodia::derivar`: pepper `b""` → `b"mutante"` | `una_clave_derivada_de_2026_no_ha_cambiado` |
| `firma::canonico`: `to_vec` → `to_vec_pretty` | `el_canonico_ordena_las_claves` (ya existía) |

**El mismo mutante de `dict()` de la primera fila pone roja también
`firma::una_firma_de_2026_sigue_verificando`**, y ése es el dato que justifica el
sexto vector. No va como fila aparte a propósito: es un mutante, no dos, y
listarlo dos veces hacía leer la tabla como si hubiera ocho.

Con el alfabeto cambiado, en `firma.rs` se ponen rojas **dos** de las tres
pruebas nuevas —`una_firma_de_2026_sigue_verificando` y
`el_vector_de_firma_discrimina`, ésta por `Invalida` y no por `Alterada`— y las
**seis que ya existían siguen en VERDE**: `firma_valida_verifica`,
`un_cambio_posterior_se_detecta_como_alterada`, `otra_clave_no_verifica` y las
tres de entrada inválida. Las seis firman y verifican con el MISMO binario, así
que un cambio de formato les sale coherente consigo mismo. Llevaban desde
siempre pareciendo cobertura de `firma`, y no cubrían lo único que no se puede
rehacer: una firma ya emitida.

Dos matices del sexto que conviene no leer de más, los dos medidos en la
revisión de guaca#18:

- **`el_vector_de_firma_discrimina` no es un control independiente**, es un
  segundo ancla del mismo formato: cae con el mismo mutante. El control de
  verdad de la pareja es otro —romper la comparación del payload en
  `firma::verificar`—, y ahí sí: `una_firma_de_2026_sigue_verificando` queda
  VERDE y solo cae su pareja. Que es exactamente para lo que existe.
- **El vector ancla la CODIFICACIÓN, no la fuerza del esquema.** Si una versión
  futura de quipu dejara de verificar la mitad ML-DSA y comprobara solo Ed25519,
  la firma congelada seguiría verificando y las tres pruebas seguirían verdes
  mientras la propiedad post-cuántica desaparece en silencio. Eso no lo puede ver
  ninguna prueba de guaca —es del lado de quipu—, y por eso queda escrito: su
  verde **no** dice «la firma híbrida sigue siendo híbrida».

De ese último mutante salió el dato que justifica el quinto vector, y vale
guardarlo: con el pepper cambiado, `una_clave_derivada_de_2026_no_ha_cambiado`
se puso ROJA mientras `la_derivacion_es_determinista` y
`distinto_salt_da_distinta_clave` **siguieron en verde**. Las dos comparaban
`derivar()` contra `derivar()` en el mismo binario, que es exactamente el
defecto que esta lista existe para cerrar — y llevaban desde siempre pareciendo
cobertura.

**Si una de esas se pone roja, NO se regenera el literal.** Roja significa que lo
guardado hasta hoy dejó de leerse: archivos cifrados que no abren, bitácoras que
se acusan solas de manipuladas, sesiones cerradas de golpe. Es una rotura de
compatibilidad que se decide y se comunica, no un vector que envejeció.

La única que sí puede envejecer legítimamente es la de `sesion`, porque su token
lleva caducidad —2226—; por eso lleva al lado
`el_vector_de_sesion_no_esta_a_punto_de_caducar`, que avisa con diez años de
margen y dice cómo regenerarlo.

## El contrato con las aplicaciones que la consumen

**guaca no tiene estado, ni base de datos, ni framework web, y no los va a
tener.** La app trae sus filas y guaca decide; la app guarda las columnas que
guaca devuelve. Es lo que permite que la misma regla valga en medico e informes
sin arrastrarles un `sqlx` ni un `axum`.

- `freno::evaluar(intentos, ahora)` recibe las marcas de tiempo **sin parsear**,
  a propósito: qué hacer con una fecha ilegible es una decisión de seguridad, y
  si la app parsea antes de llamar, se queda ella con la decisión —que es justo
  lo que este módulo existe para evitar—. Las dos decisiones van en la dirección
  conservadora: un *fallo* ilegible cuenta como recién ocurrido, un *acierto*
  ilegible **no** borra la cuenta de fallos.
- `auditoria::sellar_con` / `verificar_con` toman el firmante como *closure*: el
  esquema de firma lo pone el llamante. Así tunjo le inyecta su firma **triple**
  (Ed25519 + ML-DSA-87 + SLH-DSA) para la cadena de custodia mientras medico e
  informes usan el atajo `sellar`/`verificar` con la doble por defecto. Al tocar
  la cadena, el camino genérico es el que hay que mantener; los atajos son
  azúcar sobre él.
- `freno::corte_retencion` existe para que el `DELETE` de la app y el conteo de
  `evaluar` usen **el mismo borde**. Si aparece un segundo borde en algún sitio,
  es un defecto.

**`UMBRAL`, `BASE_SEGUNDOS`, `TOPE_SEGUNDOS` y `RETENCION_HORAS` son la política
de seguridad de dos productos.** Cambiar cualquiera es un cambio de tres
repositorios (aquí, medico e informes), y sus pruebas de ruta afirman el mismo
borde que las de aquí: tienen que decir lo mismo. El comentario de `espera_de`
guarda el porqué de `<` y no `<=` — lo cazó la prueba de la ruta, no las de este
crate.

Lo que el freno **no** resuelve, y no debe aparentar que sí: el relleno de
credenciales desde muchas máquinas contra muchas cuentas. Contra eso va el
segundo factor. Este módulo es su prerrequisito, no su sustituto.

## Cómo llega guaca a sus consumidores

**No está publicada en crates.io** (verificado 2026-08-04 contra el índice
sparse: `NoSuchKey`). Los tres consumidores la fijan por **`rev` de git**, nunca
por tag —un tag es mutable, y moverlo a un commit malicioso nos lo traería al
construir: es el ataque Atomic Arch—:

**Esto se MIDE, no se recuerda.** Cada consumidor se lleva desde su propia
instancia, así que su `rev` y sus llamadas cambian sin que aquí ocurra nada — el
2026-08-04 los dos primeros pasaron de `2ffe134` a `d786d1c` mientras se escribía
esta misma sección. Los dos comandos, probados tal cual:

```bash
grep -rho 'guaca::[a-z_]*' /mnt/data/medico /mnt/data/informes /mnt/data/tunjo \
  --include=*.rs | sort | uniq -c
grep -rn 'guaca = ' /mnt/data/medico/Cargo.toml \
  /mnt/data/informes/rust/siger-api/Cargo.toml /mnt/data/tunjo/Cargo.toml
```

Lo estable es **qué módulo usa cada uno** —eso solo cambia cuando alguien decide
usar otro—; el número de llamadas se mueve cada tarde y no vale la pena fijarlo
aquí.

| Consumidor | Qué módulos usa | `rev` (medido 2026-08-04) |
|---|---|---|
| `/mnt/data/medico` | `firma`, `freno`, `auditoria`, `reposo` | `d786d1c` (= tag `v0.4.0`) |
| `/mnt/data/informes` | `freno`, `reposo` (cifrado de entregas) | `d786d1c`, `version = "0.4"` |
| `/mnt/data/tunjo` | `auditoria` con firmante triple propio | `9d26cce` (= tag `v0.3.0`) |

**`claves` y `sesion` YA se usan — `informes` migró.** Hasta el 2026-08-04 esto
decía «no los usa NADIE: cero llamadas en los tres», y describía el trabajo que
faltaba: `informes` hasheaba por su cuenta con `SaltString::generate(&mut
OsRng)`. Recontado el **2026-08-05**, la absorción ocurrió: `guaca::claves::hashear`
se llama desde `siger-api/src/main.rs:107` y `importar.rs:474`, y el censo por
módulo en los consumidores queda así:

| Módulo | Llamadas | |
|---|---|---|
| `claves` | 31 | |
| `firma` | 28 | |
| `freno` | 27 | lo comparten `informes` y `medico` |
| `reposo` | 21 | |
| `sesion` | 11 | |
| `auditoria` | 4 | |
| `custodia` | **0** | nadie todavía — ver abajo |

**`custodia` es el único que sigue sin un solo cliente**, y esa es ahora la
frase que describe trabajo pendiente. No sobra: es el respaldo de la clave de
firma partida con Shamir, y quien debería consumirlo aún guarda la clave en el
entorno. **Su vector fijo se capturó igualmente, y a propósito antes del primer
cliente**: hacerlo hoy cuesta una prueba; hacerlo después obliga a elegir entre
romperle la bóveda a alguien o congelar un KDF sin saber cuál era.

Queda un rastro de la etapa anterior que conviene mirar cuando se toque
`informes`: su `Cargo.toml` sigue declarando `argon2` y `password-hash`, y hay
un `SaltString::generate` en `pruebas_cronograma.rs:34`. Si ya solo sirven a las
pruebas, son dependencias que se pueden bajar a `dev-dependencies` — pero eso se
mide en `informes`, no se supone desde aquí.

**Por qué el tag `v0.4.0` está en `d786d1c` y no en `2ffe134`**, que es donde se
subió el número y donde apuntaban los dos consumidores hasta esa tarde: entre
esos dos commits `src/`, `Cargo.toml` y `deny.toml` son **idénticos** —la
librería es la misma— y lo único que añade `d786d1c` es el archivo `LICENSE`.
Etiquetar `2ffe134` habría dejado una referencia pública y permanente a un árbol
sin licencia, que en un repositorio público GitHub lee como «todos los derechos
reservados». Un tag no se mueve; el sitio importa.

Mientras apuntaron a `2ffe134`, medico e informes **vendorizaban un árbol sin
`LICENSE`** — mismo código, árbol incompleto. Los dos subieron a `d786d1c` el
mismo 2026-08-04, cada uno desde su instancia. Se deja escrito porque es el modo
de fallo, no el incidente: **un `rev` a pelo no dice de qué versión sale**, y
cualquier commit vale como ancla aunque le falte medio árbol. Fijar el commit del
tag lo cierra.

**Publicar aquí no actualiza a nadie.** Subir la versión obliga a editar el `rev`
en cada consumidor que deba recibirlo, y eso es la directiva 24 en la misma
pasada — el hook de aislamiento preguntará al escribir en `medico`, `informes` o
`tunjo`, y hay que aceptarlo, no dejarlo anotado.

**Hacia abajo, guaca va SIEMPRE a la versión actual de Quipu** — hoy
`quipu = "0.11"`, resuelto a `0.11.0` en el `Cargo.lock`. Es una regla de la
familia, decidida por Juan el **2026-08-05**, y sustituye a la decisión que
estuvo escrita aquí unas horas de quedarse en la 0.10.

**El motivo es que Quipu es NUESTRA.** La directiva 35 —agotar la línea actual,
el salto mayor con motivo y nunca por inercia— existe para no perseguir el
*major* de un tercero entre visitas al cliente. Aquí las dos puntas son de casa:
quien corta la release decide también cuándo la toman los derivados. Y quedarse
atrás tiene un coste que ir al día no tiene: mientras guaca y tunjo no vayan
parejos, el binario de tunjo acaba con **dos copias de la pila cripto** —lo suyo
y lo que arrastra guaca por el `rev`—, medido el 2026-08-05.

**LA PUERTA, que es lo que separa la regla de la inercia: se sube, y si un
VECTOR FIJO se pone rojo, la subida SE DETIENE y vuelve a ser una decisión.** Un
rojo ahí no es una prueba quisquillosa: dice que lo ya cifrado dejó de abrirse.
No se regenera el literal — eso convierte una rotura de compatibilidad en un
verde. Los **seis** vectores están arriba, con la tabla de mutantes que demuestra
que cada uno discrimina.

**Y hoy nada lo IMPIDE: solo está escrito.** No hay hook, ni `CODEOWNERS`, ni
comprobación de CI que detecte que un archivo de `src/vectores/` cambió en un PR
— es la directiva 6 sin cumplir (máquina que impide > prueba que falla >
directiva que recordar) justo donde más caro sale, porque el arreglo tentador
—regenerar el literal y ver verde— es *más barato* que el correcto. Y el paso a
archivos lo empeora un poco frente a los cinco literales en línea: un literal
alterado salta a la vista en el diff de `firma.rs`; un `firma_2026.txt` de 5883
caracteres reescrito entero es una sola línea `+`/`-` que nadie va a leer. Está
registrado como tarea `#489`, y la guardia barata que sí discriminaría es un job
que falle si el diff toca `src/vectores/` y el PR no lleva etiqueta explícita de
rotura de compatibilidad.

**El orden con tunjo son TRES pasos, no dos**, y el tercero es el que se olvida:

1. guaca sube `quipu` y entra en `main`.
2. tunjo sube `quipu` **y** mueve el `rev` de guaca a ese commit, **en el mismo
   commit suyo**. Si solo sube `quipu`, sigue arrastrando la versión vieja por
   el `rev` viejo.
3. Control de que salió bien, antes de dar nada por bueno:
   `grep -c '^name = "quipu"$' Cargo.lock` tiene que dar **1** en tunjo.

`chuspa` no entra en la regla: compila por `path = "../decod"`, así que ya va
contra el árbol por definición.

**La compatibilidad con 0.11 SÍ está verificada** (2026-08-05). Aquí decía que no
lo estaba y que no se podía suponer; se midió, y el resultado es que guaca
compila y pasa **56/56** contra `quipu 0.11.0` en un worktree aislado, con los
cinco vectores fijos dentro — incluido `un_blob_de_2026_sigue_descifrando`, que
es lo que prueba que un blob escrito con 0.10 se abre con 0.11.

Lo que faltaba era `custodia::derivar`, y **ya no falta**: `derive_master_key`
con `KdfParams::default()` da la MISMA maestra byte a byte bajo 0.10 y 0.11
—medido con un arnés pareado, un binario por versión, comprobando en los dos
`Cargo.lock` que cada uno enlazó la suya—. Y para que eso deje de ser una
medición de una tarde, la clave quedó pegada como **vector fijo** en
`una_clave_derivada_de_2026_no_ha_cambiado`. Con el mutante puesto en el código
medido, esa prueba se pone roja y las dos que ya existían siguen en VERDE: son
ciegas al KDF porque comparan `derivar()` contra `derivar()` en el mismo
binario.

Lo que sigue SIN verificar es el otro lado del acoplamiento, y es tarea de
tunjo: `src/clave.rs` tampoco tiene vector fijo. Que un `.clave` de 0.10 abra
con 0.11 está comprobado cruzando los binarios reales, pero nada lo sujeta.

**Los tags son anotados, uno por versión, y `v0.4.0` se puso el 2026-08-04** —
faltaba desde que se subió el número—. Los cuatro, comprobados en `origin`:
`v0.1.0`→`40fb4b4`, `v0.2.0`→`d3d7ab1`, `v0.3.0`→`9d26cce`, `v0.4.0`→`d786d1c`.
El mensaje sigue la forma de los anteriores: `guaca X.Y.Z — <qué trae>`.

Un tag **no dispara el CI** (el workflow solo escucha `push` a `main` y
`pull_request`), así que un tag por sí solo no prueba nada. Lo que ancla el
veredicto es que su commit tenga su propia corrida verde: `d786d1c` la tiene.

## CI y merge

Dos jobs en `.github/workflows/ci.yml`: `test + clippy` y `cargo-deny`. Se
dispara en `push` **solo a `main`** y en `pull_request` a `main` — cada commit se
prueba una vez, no dos, porque una rama con PR abierto disparaba los dos eventos.
**Consecuencia deliberada: una rama empujada sin PR no tiene CI.** El flujo es
rama → PR → merge.

guaca es público, así que sus minutos de Actions son gratis: la suspensión de
`push`/`merge` por cupo agotado que describe la configuración general afecta a
los repos privados, no a este.

**Las tres piezas de esto son distintas y se confunden:** `dependabot.yml`
programa las actualizaciones **rutinarias**; las **alertas** de Dependabot y las
**correcciones automáticas** son ajustes del repositorio, no archivos, y se
encendieron el 2026-08-04 (estaban las dos apagadas). Se comprueban así, y el
segundo comando es el bueno porque responde con cuerpo en vez de con un código:

```bash
gh api repos/isazajuancarlos/guaca/vulnerability-alerts -i | head -1  # 204=on, 404=off
gh api repos/isazajuancarlos/guaca/automated-security-fixes           # {"enabled":true,...}
gh api repos/isazajuancarlos/guaca/dependency-graph/sbom \
  --jq '[.sbom.packages[]|select(.name|test("/")|not)]|length'        # crates que VE
```

Ese último es el que importa: si devuelve 10 y no ~119, el lock no está en la
rama por defecto y la alarma está ciega otra vez.

**Las actualizaciones las avisa `dependabot.yml`**, semanal, agrupando lo
compatible en un solo PR y dejando FUERA los saltos de línea mayor — cada uno de
esos es una decisión con motivo (directiva 35), y hay cinco esperando: `quipu`
0.11 (deliberado: cambia `Options.codebook_id`), `argon2` 0.6 (todavía RC, así
que no), `password-hash` 0.6 (bloqueado por argon2 0.5), `hmac` 0.13 y `sha2`
0.11 (la generación nueva de RustCrypto, que desincronizaría con el `sha2` que
trae Quipu). Ninguno es de seguridad — medido el 2026-08-04 con `cargo deny check
advisories` contra una base de 1169 avisos actualizada ese día.

**`password-hash` parece una dependencia muerta y no lo es.** `claves.rs` no la
importa —usa el reexport `argon2::password_hash::…`— y `cargo tree` la enseña
colgando de argon2, así que se lee como una línea que sobra. Lo que hace es
habilitar `OsRng`: `password-hash/getrandom` → `rand_core/getrandom` → `pub use
os::OsRng`, y argon2 0.5 no activa ninguna de las dos. Quitarla mata el build con
`E0432: unresolved import argon2::password_hash::rand_core::OsRng` — comprobado
quitándola de verdad, no razonado. El motivo va escrito en la propia línea del
`Cargo.toml`, que es donde alguien iría a borrarla.

**Antes de mergear a `main`: `/security-review` desde ESTA carpeta** (directiva
25 — guaca está en la lista de repos sensibles). La skill construye su diff con
el `cwd`; lanzada desde otro repo da un diff vacío en silencio.

**Salvo que el diff sea inerte** —prosa y comentarios, nada más—, exención que se
acotó el 2026-08-04 precisamente aquí: la revisión corrió cuatro veces en una
tarde y tres fueron sobre diffs sin una línea ejecutable. El comando que lo
decide está en la directiva 25; se salta **diciéndolo**, nunca en silencio. Ojo
con la tentación de ampliar la exención a «configuración declarativa»: un
`dependabot.yml` que gana `target-branch` apaga las alertas de CVE sin ejecutar
nada, y un workflow puede cambiar `permissions:` sin añadir un solo `run:`.

## Estilo del código

Todo en español: módulos, funciones, tipos, variantes de enum y nombres de
prueba. El submódulo de pruebas se llama `mod pruebas`, no `mod tests`.

**Los comentarios explican la decisión, no la mecánica**, y en particular lo que
se rechazó: por qué no se bloquea la cuenta, por qué el techo son cinco minutos,
por qué el contenido va anidado en la preimagen, por qué un `Result` se colapsa a
`Option`. Un comentario que repite lo que hace la línea siguiente sobra; uno que
guarda el argumento de un descarte es lo que impide que alguien lo reabra dentro
de un año. Al cambiar la decisión, se cambia el comentario en la misma edición.

**Cada salvaguarda nace con su pareja de pruebas** (directiva 33): la que TIENE
que ver y la que TIENE que no ver. Los ejemplos vivos son
`sesion::cambiar_el_usuario_invalida_la_firma` («sin ella, un verificador que
siempre devuelve `Some` pasaría la anterior»), el par
`entrar_bien_borra_la_cuenta_de_fallos` /
`los_fallos_posteriores_al_acierto_si_cuentan`, y el par de marcas ilegibles del
freno. Una prueba nueva sin su reverso no está terminada.

Los errores **no dicen de más**: `custodia` no revela qué compartición estaba
corrupta, `sesion::verificar` devuelve un solo `None` para firma mala, formato
raro y caducidad, y `claves::verificar` trata un hash ilegible como «no
coincide». Eso también es la decisión, no descuido.
