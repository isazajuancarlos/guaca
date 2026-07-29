<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# guaca

**Protección en reposo para aplicaciones, sobre [Quipu](https://crates.io/crates/quipu).**

_Una guaca es un tesoro enterrado y protegido — aquí, los datos en reposo._

Dos capas, una fachada delgada (no reimplementa criptografía):

- **`reposo`** — cifrado autenticado de archivos y blobs sensibles (KDF Argon2 +
  AEAD + padding que oculta la longitud). Para imágenes clínicas, entregas,
  cualquier archivo que no deba leerse desde el disco.
- **`firma`** — integridad y no repudio post-cuánticos (Ed25519 + ML-DSA-87) de un
  registro. La firma se rompe si el registro cambia; distingue «alterado» de
  «firma inválida».

## Por qué existe

Medida real: dos aplicaciones (medico e informes) copiaban la misma sesión y el
mismo endurecimiento de secreto, y **las copias ya habían divergido** —una mejora
de seguridad se quedó en un solo lado—. El código de seguridad duplicado es código
de seguridad divergente. En `guaca` vive una vez, se audita una vez, se arregla
una vez.

## Uso

```rust
use guaca::{reposo, firma};

// Cifrar un archivo en reposo
let blob = reposo::cifrar(bytes, &frase_del_despliegue);
let claro = reposo::descifrar(&blob, &frase_del_despliegue)?;

// Firmar un registro y verificarlo después
let (clave_publica, clave_privada) = firma::generar_claves();
let datos = firma::canonico(&campos);      // JSON canónico determinista
let sig = firma::firmar(&datos, &clave_privada).unwrap();
assert_eq!(firma::verificar(&datos, &sig, &clave_publica), firma::Verificacion::Valida);
```

**La frase de cifrado y la clave privada de firma NUNCA se guardan junto al dato.**
Vienen de un secreto de despliegue (o de un HSM / repartidas con Shamir para
respaldo).

## Licencia

AGPL-3.0-or-later, con licencia comercial disponible (misma política que Quipu).
