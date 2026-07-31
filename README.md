# 🧠🔬 RAM Forensic Agent — GLOBALSECURE

**Local, evidence-grounded memory-forensics assistant** that connects a local LLM
(via [LM Studio](https://lmstudio.ai)) to [Volatility 3](https://github.com/volatilityfoundation/volatility3),
letting an investigator ask questions in natural language and get answers based
**only** on real evidence extracted from a memory dump — never hallucinated.

> **Agente forense de memoria RAM, local y sin alucinaciones**, que conecta un LLM
> local (vía LM Studio) con Volatility 3, permitiendo al investigador hacer preguntas
> en lenguaje natural y recibir respuestas basadas **solo** en evidencia real extraída
> del dump de memoria — nunca inventadas.

---

**Author / Autor:** Manuel Moreno — [GLOBALSECURE](https://www.globalsecure.cl)
🌐 [www.globalsecure.cl](https://www.globalsecure.cl)

---

## 🇬🇧 English

### Overview

`agent.py` is a terminal application that turns a locally-hosted language model into
a **memory-forensics analyst**. It orchestrates Volatility 3 through a
**ReAct loop** (Reason → Act → Observe): the model decides which Volatility plugin
to run, the agent executes it against the dump, feeds the *real* output back to the
model, and repeats until the model can answer — always citing the plugin that
produced each fact.

Everything runs **100 % offline**. The memory dump and its contents never leave the
analyst's machine, which is essential when handling forensic evidence.

### Key features

- 🔒 **Fully local / air-gapped** — LLM served by LM Studio on `127.0.0.1`; no cloud, no data exfiltration.
- 🚫 **Anti-hallucination by design**:
  - Strict plugin **whitelist** — only vetted read-only plugins reach the shell.
  - System prompt forbids inventing PIDs, IPs, commands, modules or timestamps.
  - The model must **cite the plugin** behind every stated fact.
  - Low temperature + frequency/presence penalties to keep answers factual and loop-free.
- 🖥️ **Multi-OS** — Linux, Windows and macOS dumps (165+ plugins, filtered by the OS you select).
- 🧭 **Guided plugin selection** — an intent→plugin cheat-sheet in the prompt stops the model from guessing plugin names.
- 🩹 **Self-healing execution**:
  - **Auto-correction** of malformed plugin names (`windows.pslist.PsScan` → `windows.psscan.PsScan`).
  - **Automatic fallback** from linked-list walkers to pool scanners when a plugin returns empty (`pslist` → `psscan`, `netstat` → `netscan`).
  - **Degeneration detector** discards repetition-loop output from weak/quantized models.
  - **Stall guard** aborts gracefully instead of burning turns.
- 💾 **Per-case caching** — plugin outputs are cached per dump so repeated questions are instant.
- 🧩 **Custom symbol support** — bundled Volatility symbols plus an optional extra ISF directory for custom kernels (e.g. Oracle UEK built with `dwarf2json`).

### How it works

```
Investigator question
        │
        ▼
┌─────────────────────┐     RUN_PLUGIN: windows.psscan.PsScan
│   Local LLM (ReAct) │ ───────────────────────────────────────►┐
│   via LM Studio     │                                         │
│                     │ ◄─── real plugin output (evidence) ─────┤
└─────────────────────┘                                         │
        │                                              ┌─────────────────┐
        │ FINAL_ANSWER: ... (citing plugins)           │  Volatility 3   │
        ▼                                              │  on the dump    │
   Grounded answer                                     └─────────────────┘
```

### Requirements

- **Python 3.10+**
- **[Volatility 3](https://github.com/volatilityfoundation/volatility3) v2.28.0**
- **[LM Studio](https://lmstudio.ai)** with a model loaded and its local server running
- Python dependency: `requests` (see `requirements.txt`)

**Recommended model:** `qwen2.5-14b-instruct-1m` — a clean *Instruct* model with a
huge context window. Avoid "thinking", "uncensored/obliterated" or heavily-quantized
(`iq-ultra`) variants: they degrade instruction-following and factual grounding, which
is exactly what a forensic agent must not lose.

### Installation

```bash
# 1. Clone / place this folder next to your Volatility 3 install
#    (agent.py expects ../volatility3-2.28.0/volatility3-2.28.0/vol.py)

# 2. Install the Python dependency
pip install -r requirements.txt

# 3. In LM Studio: download and LOAD a model, then start the local server
#    (Developer tab → Start Server, default port 1234)
```

### Configuration

Edit the `CONFIGURACIÓN DE HERRAMIENTA` block at the top of `agent.py`:

| Setting | Default | Purpose |
|---|---|---|
| `LM_BASE` | `http://127.0.0.1:1234` | LM Studio server URL |
| `LM_MODEL` | `qwen2.5-14b-instruct-1m` | Model to use (must be loaded; set `None` to auto-pick) |
| `LM_TEMP` | `0.1` | Low temperature → factual answers |
| `LM_MAXTOK` | `4096` | Max tokens per reply |
| `LM_TIMEOUT` | `600` | Seconds to wait per model call (large prompts need time) |
| `LM_DISABLE_THINKING` | `False` | Append `/no_think` (only for Qwen3 "thinking" models) |
| `VOL_PY` | *(relative)* | Path to `vol.py` |
| `MAX_LINES` | `800` | Max plugin output lines fed to the model |
| `MAX_TURNS` | `8` | Max ReAct iterations per question |

### Usage

```bash
python agent.py
```

On startup the agent will:

1. Verify Volatility, symbols and the LM Studio connection.
2. Ask for the **path to the memory dump**.
3. Ask for an optional **extra ISF symbol directory** (for custom kernels).
4. Ask you to identify the **operating system** of the dump (Linux / Windows / macOS).
5. Drop you into an interactive prompt.

In-session commands:

| Command | Action |
|---|---|
| *(any text)* | Send a forensic question to the agent |
| `plugins` | List the authorized plugins for the selected OS |
| `cache clear` | Delete cached plugin outputs for the current case |
| `historial` | Show questions asked this session |
| `salir` | Exit |

**Example question:**

```
Investigador> list the running processes and check for connections to external IPs
```

The agent runs `windows.psscan.PsScan` and `windows.netscan.NetScan`, then answers
citing the exact processes and external IP addresses found in the evidence.

### Security notes

- Only **read-only** Volatility plugins are whitelisted — the agent never modifies the dump or the host.
- The LLM output is treated as **untrusted**: plugin names are validated against the whitelist before any subprocess call.
- No network calls other than to the local LM Studio server (Windows symbol PDBs are the one exception — Volatility may fetch them from Microsoft's symbol server on first use; run on a machine with controlled internet if that matters for your chain of custody).

---

## 🇪🇸 Español

### Descripción

`agent.py` es una aplicación de terminal que convierte un modelo de lenguaje local
en un **analista forense de memoria**. Orquesta Volatility 3 mediante un
**bucle ReAct** (Razonar → Actuar → Observar): el modelo decide qué plugin de
Volatility ejecutar, el agente lo corre contra el dump, le devuelve el output *real*
al modelo, y repite hasta poder responder — siempre **citando el plugin** que produjo
cada dato.

Todo corre **100 % offline**. El dump de memoria y su contenido nunca salen de la
máquina del analista, algo esencial al manejar evidencia forense.

### Características principales

- 🔒 **Totalmente local / aislado** — el LLM lo sirve LM Studio en `127.0.0.1`; sin nube, sin fuga de datos.
- 🚫 **Anti-alucinación por diseño**:
  - **Lista blanca** estricta de plugins — solo plugins de solo-lectura verificados llegan al shell.
  - El prompt de sistema prohíbe inventar PIDs, IPs, comandos, módulos o timestamps.
  - El modelo debe **citar el plugin** detrás de cada dato afirmado.
  - Temperatura baja + penalizaciones de frecuencia/presencia para respuestas factuales y sin loops.
- 🖥️ **Multi-SO** — dumps de Linux, Windows y macOS (más de 165 plugins, filtrados según el SO que elijas).
- 🧭 **Selección guiada de plugins** — una guía intención→plugin en el prompt evita que el modelo adivine nombres.
- 🩹 **Ejecución auto-reparable**:
  - **Autocorrección** de nombres de plugin mal formados (`windows.pslist.PsScan` → `windows.psscan.PsScan`).
  - **Fallback automático** de recorredores de lista enlazada a escáneres de pool cuando un plugin viene vacío (`pslist` → `psscan`, `netstat` → `netscan`).
  - **Detector de degeneración** que descarta salidas en loop de modelos débiles/cuantizados.
  - **Guardia de estancamiento** que aborta con elegancia en vez de quemar turnos.
- 💾 **Caché por caso** — los outputs se cachean por dump, así preguntas repetidas son instantáneas.
- 🧩 **Soporte de símbolos custom** — símbolos integrados de Volatility más un directorio ISF adicional opcional para kernels custom (ej. Oracle UEK generado con `dwarf2json`).

### Cómo funciona

```
Pregunta del investigador
        │
        ▼
┌─────────────────────┐     RUN_PLUGIN: windows.psscan.PsScan
│  LLM local (ReAct)  │ ───────────────────────────────────────►┐
│  vía LM Studio      │                                         │
│                     │ ◄─── output real del plugin (evidencia)─┤
└─────────────────────┘                                         │
        │                                              ┌─────────────────┐
        │ FINAL_ANSWER: ... (citando plugins)          │  Volatility 3   │
        ▼                                              │  sobre el dump  │
  Respuesta fundamentada                               └─────────────────┘
```

### Requisitos

- **Python 3.10+**
- **[Volatility 3](https://github.com/volatilityfoundation/volatility3) v2.28.0**
- **[LM Studio](https://lmstudio.ai)** con un modelo cargado y su servidor local activo
- Dependencia Python: `requests` (ver `requirements.txt`)

**Modelo recomendado:** `qwen2.5-14b-instruct-1m` — un modelo *Instruct* limpio y con
contexto enorme. Evita variantes "thinking", "uncensored/obliterated" o muy
cuantizadas (`iq-ultra`): degradan el seguimiento de instrucciones y la factualidad,
justo lo que un agente forense no puede perder.

### Instalación

```bash
# 1. Coloca esta carpeta junto a tu instalación de Volatility 3
#    (agent.py espera ../volatility3-2.28.0/volatility3-2.28.0/vol.py)

# 2. Instala la dependencia de Python
pip install -r requirements.txt

# 3. En LM Studio: descarga y CARGA un modelo, luego inicia el servidor local
#    (pestaña Developer → Start Server, puerto por defecto 1234)
```

### Configuración

Edita el bloque `CONFIGURACIÓN DE HERRAMIENTA` al inicio de `agent.py`:

| Parámetro | Valor por defecto | Propósito |
|---|---|---|
| `LM_BASE` | `http://127.0.0.1:1234` | URL del servidor LM Studio |
| `LM_MODEL` | `qwen2.5-14b-instruct-1m` | Modelo a usar (debe estar cargado; `None` para autoelegir) |
| `LM_TEMP` | `0.1` | Temperatura baja → respuestas factuales |
| `LM_MAXTOK` | `4096` | Tokens máximos por respuesta |
| `LM_TIMEOUT` | `600` | Segundos de espera por llamada (prompts grandes tardan) |
| `LM_DISABLE_THINKING` | `False` | Añade `/no_think` (solo para modelos Qwen3 "thinking") |
| `VOL_PY` | *(relativo)* | Ruta a `vol.py` |
| `MAX_LINES` | `800` | Líneas máximas de output entregadas al modelo |
| `MAX_TURNS` | `8` | Iteraciones máximas del ReAct por pregunta |

### Uso

```bash
python agent.py
```

Al iniciar, el agente:

1. Verifica Volatility, los símbolos y la conexión con LM Studio.
2. Pide la **ruta al dump de memoria**.
3. Pide un **directorio ISF adicional** opcional (para kernels custom).
4. Te pide identificar el **sistema operativo** del dump (Linux / Windows / macOS).
5. Te deja en un prompt interactivo.

Comandos en sesión:

| Comando | Acción |
|---|---|
| *(cualquier texto)* | Envía una pregunta forense al agente |
| `plugins` | Lista los plugins autorizados para el SO elegido |
| `cache clear` | Borra los outputs cacheados del caso actual |
| `historial` | Muestra las preguntas de esta sesión |
| `salir` | Termina |

**Pregunta de ejemplo:**

```
Investigador> revisa los procesos en ejecución y si hay conexiones hacia IPs externas
```

El agente ejecuta `windows.psscan.PsScan` y `windows.netscan.NetScan`, y responde
citando los procesos exactos y las direcciones IP externas halladas en la evidencia.

### Notas de seguridad

- Solo se permiten plugins de Volatility de **solo lectura** — el agente nunca modifica el dump ni el host.
- La salida del LLM se trata como **no confiable**: los nombres de plugin se validan contra la lista blanca antes de cualquier llamada a subprocess.
- No hay llamadas de red salvo al servidor local de LM Studio (la excepción son los PDB de símbolos de Windows: Volatility puede descargarlos del servidor de símbolos de Microsoft la primera vez; ejecuta en una máquina con internet controlado si esto afecta tu cadena de custodia).

---

## 📄 License / Licencia

Internal tool developed for **GLOBALSECURE**.
Herramienta interna desarrollada para **GLOBALSECURE**.

## 👤 Author / Autor

**Manuel Moreno**
GLOBALSECURE — 🌐 [www.globalsecure.cl](https://www.globalsecure.cl)
