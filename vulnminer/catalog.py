"""Catalogo completo. La cobertura es un subconjunto explicitamente declarado."""
WEB = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}
API = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}
# These correspondences describe the controlled scenarios, not a universal bijection.
SCENARIOS = {
    "sql": dict(cwe="CWE-89", labels=["A05:2025"], title="Consulta SQL construida con entrada externa", severity="Alta", reason="La entrada podria modificar la consulta y acceder a datos.", remedy="Usar consultas parametrizadas y limitar privilegios de la cuenta de base de datos."),
    "crypto": dict(cwe="CWE-327", labels=["A04:2025"], title="Algoritmo criptografico debil en contexto sensible", severity="Media", reason="MD5 o SHA-1 no proporcionan resistencia adecuada en este contexto.", remedy="Usar Argon2id para contrasenas y algoritmos actuales adecuados al uso; revisar el contexto."),
    "debug": dict(cwe="CWE-489", labels=["A02:2025", "API8:2023"], title="Depuracion habilitada en configuracion de servicio", severity="Media", reason="La depuracion podria revelar detalles internos o exponer funciones de diagnostico.", remedy="Deshabilitar depuracion en produccion y separar perfiles de desarrollo y despliegue."),
    "jwt": dict(cwe="CWE-347", labels=["A07:2025", "API2:2023"], title="Token de autenticacion sin verificacion de firma", severity="Alta", reason="Una firma no verificada podria permitir suplantacion de identidad.", remedy="Verificar firma, algoritmo permitido, expiracion, emisor y audiencia del JWT."),
    "ssrf": dict(cwe="CWE-918", labels=["A01:2025", "API7:2023"], title="Destino de solicitud HTTP controlado externamente", severity="Alta", reason="Un destino no restringido podria alcanzar recursos internos.", remedy="Aplicar allowlist de destinos, validar IP y DNS, bloquear redes internas y redirecciones no validadas."),
    "deserialize": dict(cwe="CWE-502", labels=["A08:2025"], title="Deserializacion de entrada externa", severity="Alta", reason="Un deserializador de objetos puede ejecutar comportamiento peligroso.", remedy="Usar JSON con validacion de esquema; evitar pickle o node-serialize para datos no confiables."),
    "tls": dict(cwe="CWE-295", labels=["A07:2025", "API10:2023"], title="Verificacion TLS deshabilitada al consumir API externa", severity="Alta", reason="La identidad del servidor remoto no queda autenticada.", remedy="Habilitar verificacion del certificado y usar una CA confiable; validar respuestas externas."),
}
EVALUATED = set(label for s in SCENARIOS.values() for label in s["labels"])


def catalog():
    return [dict(id=k, name=v, status="Evaluada en casos controlados" if k in EVALUATED else "No evaluada: sin datos ni detector suficiente") for k, v in (WEB | API).items()]
