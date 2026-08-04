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
cargo test                      # 48 pruebas, ~29 s en debug (medido 2026-08-04)
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

`Cargo.lock` **no se versiona** (es librería). Lo que fija la versión de guaca en
sus consumidores es el `rev` de git de ellos, no este lock.

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
- **`auditoria::preimagen`** — `{"cont": …, "prev": hex, "seq": n}`. Cambiarla
  invalida todas las cadenas ya selladas, que es precisamente lo que la cadena
  existe para hacer notar.
- **`sesion`** — el formato del token y el HMAC. Cambiarlos cierra la sesión de
  todo el mundo a la vez.

Ante cualquiera de los cuatro: versión nueva y migración explícita del
consumidor, nunca un cambio en sitio.

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

| Consumidor | Qué usa | `rev` fijado |
|---|---|---|
| `/mnt/data/medico` | `freno`, `sesion`, `claves` | `2ffe134` (= v0.4.0) |
| `/mnt/data/informes` | `reposo` (cifrado de entregas), `freno` | `2ffe134`, `version = "0.4"` |
| `/mnt/data/tunjo` | `auditoria` con firmante triple propio | `9d26cce` (= tag `v0.3.0`) |

**Publicar aquí no actualiza a nadie.** Subir la versión obliga a editar el `rev`
en cada consumidor que deba recibirlo, y eso es la directiva 24 en la misma
pasada — el hook de aislamiento preguntará al escribir en `medico`, `informes` o
`tunjo`, y hay que aceptarlo, no dejarlo anotado.

**Hacia abajo, guaca pide `quipu = "0.10"` de crates.io mientras el árbol de
decod va por `0.11.0`.** `^0.10` NO casa con 0.11: publicar Quipu 0.11 no llega
aquí sola, y subir el requisito es una decisión aparte (la 0.11 cambia el
comportamiento de `Options.codebook_id`). Verificado en el `Cargo.lock` local:
resuelve `quipu 0.10.0` de crates.io.

**Pendiente conocido: falta el tag `v0.4.0`.** `Cargo.toml` dice `0.4.0`, hay
tags hasta `v0.3.0` (local y en `origin`), y los consumidores apuntan al commit
`2ffe134` a pelo. Verificado con `git tag` y `git ls-remote --tags origin` el
2026-08-04.

## CI y merge

Dos jobs en `.github/workflows/ci.yml`: `test + clippy` y `cargo-deny`. Se
dispara en `push` **solo a `main`** y en `pull_request` a `main` — cada commit se
prueba una vez, no dos, porque una rama con PR abierto disparaba los dos eventos.
**Consecuencia deliberada: una rama empujada sin PR no tiene CI.** El flujo es
rama → PR → merge.

guaca es público, así que sus minutos de Actions son gratis: la suspensión de
`push`/`merge` por cupo agotado que describe la configuración general afecta a
los repos privados, no a este.

**Antes de mergear a `main`: `/security-review` desde ESTA carpeta** (directiva
25 — guaca está en la lista de repos sensibles). La skill construye su diff con
el `cwd`; lanzada desde otro repo da un diff vacío en silencio.

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
