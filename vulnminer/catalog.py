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
    "path": dict(cwe="CWE-22", labels=["A01:2025"], title="Acceso a archivos con posible recorrido de rutas", severity="Alta", reason="Una ruta externa podria acceder a archivos fuera del directorio autorizado.", remedy="Resolver y validar la ruta final dentro de una raiz permitida, evitando enlaces y rutas externas."),
    "redirect": dict(cwe="CWE-601", labels=["A01:2025"], title="Redireccion potencialmente controlada por entrada externa", severity="Media", reason="Un destino no validado puede dirigir a un sitio no confiable.", remedy="Permitir solo destinos locales o una lista explicita de origenes autorizados."),
    "cookie": dict(cwe="CWE-614", labels=["A02:2025"], title="Cookie con configuracion de transporte potencialmente insegura", severity="Media", reason="Una cookie sensible sin Secure puede viajar por un canal no protegido.", remedy="Habilitar Secure, HttpOnly y SameSite segun el uso; verificar HTTPS en todo el flujo."),
    "xxe": dict(cwe="CWE-611", labels=["A02:2025"], title="Procesamiento XML con posible resolucion de entidades externas", severity="Alta", reason="Una entidad externa podria revelar archivos o provocar solicitudes internas.", remedy="Deshabilitar DTD y entidades externas y usar un analizador XML endurecido."),
    "hash": dict(cwe="CWE-328", labels=["A04:2025"], title="Hash potencialmente debil en un contexto sensible", severity="Media", reason="Un hash debil puede no proteger adecuadamente secretos o integridad.", remedy="Elegir una funcion moderna adecuada al contexto y usar Argon2id para contrasenas."),
    "weakrand": dict(cwe="CWE-330", labels=["A04:2025"], title="Aleatoriedad potencialmente insuficiente para un uso de seguridad", severity="Media", reason="Un generador predecible puede debilitar tokens o identificadores secretos.", remedy="Usar secrets o SecureRandom cuando se necesite impredecibilidad criptografica."),
    "command": dict(cwe="CWE-78", labels=["A05:2025"], title="Ejecucion de comandos con posible entrada no confiable", severity="Alta", reason="La entrada puede modificar un comando del sistema.", remedy="Evitar el shell, usar una lista de argumentos y validar operaciones permitidas."),
    "xss": dict(cwe="CWE-79", labels=["A05:2025"], title="Salida HTML potencialmente construida con entrada externa", severity="Media", reason="Contenido no codificado puede interpretarse como marcado activo.", remedy="Codificar segun el contexto de salida y utilizar plantillas con escape automatico."),
    "ldap": dict(cwe="CWE-90", labels=["A05:2025"], title="Consulta LDAP potencialmente construida con entrada externa", severity="Alta", reason="La entrada puede alterar el filtro de consulta LDAP.", remedy="Usar constructores de filtros seguros y escape LDAP especifico."),
    "xpath": dict(cwe="CWE-643", labels=["A05:2025"], title="Consulta XPath potencialmente construida con entrada externa", severity="Alta", reason="La entrada puede alterar la expresion de seleccion de datos.", remedy="Usar variables XPath enlazadas y evitar concatenar entrada en expresiones."),
    "code": dict(cwe="CWE-94", labels=["A05:2025"], title="Evaluacion dinamica potencial de codigo no confiable", severity="Alta", reason="La interpretacion de entrada como codigo puede permitir ejecucion arbitraria.", remedy="Evitar eval y exec sobre datos externos y usar parsers de datos con esquema."),
    "trustboundary": dict(cwe="CWE-501", labels=["A06:2025"], title="Posible cruce de limites de confianza en estado de sesion", severity="Media", reason="La entrada externa puede modificar estado que deberia controlar la aplicacion.", remedy="Mantener claves y privilegios de sesion bajo control del servidor y validar el flujo completo."),
}
EVALUATED = set(label for s in SCENARIOS.values() for label in s["labels"])


def catalog():
    return [dict(id=k, name=v, status=("Evaluada parcialmente con Benchmark publico y/o suplemento controlado" if k in EVALUATED else "No evaluada: sin datos ni detector suficiente")) for k, v in (WEB | API).items()]
