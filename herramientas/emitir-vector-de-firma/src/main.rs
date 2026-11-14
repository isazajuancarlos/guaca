// Emite el vector fijo de FIRMA con guaca d786d1c / quipu 0.10.0.
// Lo que se congela es (clave publica, preimagen, firma). La firma no es
// reproducible —ML-DSA-87 es aleatorizada—, pero no hace falta que lo sea:
// lo que el vector afirma es que una firma EMITIDA por 0.10 sigue VERIFICANDO.
use std::collections::BTreeMap;
use serde_json::json;

fn main() {
    // Un canonico con la forma que medico persiste en historia.rs:528.
    let mut campos: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    campos.insert("documento".into(), json!("historia-clinica"));
    campos.insert("estado".into(), json!("CERRADA"));
    campos.insert("id".into(), json!(4210));
    campos.insert("momento".into(), json!("2026-08-05T09:00:00Z"));
    campos.insert("profesional".into(), json!("dra.ruiz"));
    let pre = guaca::firma::canonico(&campos);

    let (vk, sk) = guaca::firma::generar_claves();
    let firma = guaca::firma::firmar(&pre, &sk).expect("firmar");

    // Control de que este binario es de verdad el de 0.10: verifica consigo mismo.
    assert_eq!(guaca::firma::verificar(&pre, &firma, &vk), guaca::firma::Verificacion::Valida);

    let hex: String = pre.iter().map(|b| format!("{b:02x}")).collect();
    println!("PREIMAGEN_HEX={hex}");
    println!("VK={vk}");
    println!("FIRMA={firma}");
    eprintln!("preimagen en claro: {}", String::from_utf8_lossy(&pre));
}
