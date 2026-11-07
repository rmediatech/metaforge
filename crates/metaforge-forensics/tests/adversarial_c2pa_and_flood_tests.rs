use metaforge_forensics::{scan_embedded_payloads, MAX_PAYLOAD_MATCHES};

#[test]
fn test_adversarial_c2pa_ai_provenance_and_signature_flood_clamping() {
    let mut fake_img = vec![0u8; 32];
    fake_img.extend_from_slice(b"jumb...c2pa...c2ma...ComfyUI...Negative prompt: blurry");
    let findings = scan_embedded_payloads(&fake_img, fake_img.len());

    let names: Vec<&str> = findings.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"C2PA Content Provenance JUMBF Manifest"));
    assert!(names.contains(&"ISO 19566-5 JUMBF Provenance Box"));
    assert!(names.contains(&"C2PA Claim Manifest Assertion"));
    assert!(names.contains(&"ComfyUI Node Workflow Graph Footprint"));
    assert!(names.contains(&"Stable Diffusion Negative Prompt Footprint"));

    // Signature flood bomb: 2,000 repeated "eval(" strings must clamp at MAX_PAYLOAD_MATCHES (256)
    let mut flood_buf = vec![0u8; 16];
    for _ in 0..2000 {
        flood_buf.extend_from_slice(b"eval(");
    }
    let clamped = scan_embedded_payloads(&flood_buf, flood_buf.len());
    assert_eq!(clamped.len(), MAX_PAYLOAD_MATCHES);
}
