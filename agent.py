#!/usr/bin/env python3
"""
Agente Forense de RAM — GLOBALSECURE
=====================================
Conecta LM Studio con Volatility 3 para análisis forense de memoria.
Soporta dumps de Linux, Windows y macOS.
Las respuestas se basan ÚNICAMENTE en evidencia real del dump analizado.

Uso:
    python agent.py

Comandos en sesión:
    plugins      — lista plugins disponibles
    cache clear  — borra resultados cacheados del caso actual
    historial    — preguntas de esta sesión
    salir        — termina
"""

import sys
import re
import difflib
import subprocess
import hashlib
import textwrap
import requests
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURACIÓN DE HERRAMIENTA  —  rutas de instalación (no datos del caso)
# ═══════════════════════════════════════════════════════════════════════════════

LM_BASE   = "http://127.0.0.1:1234"       # URL del servidor LM Studio
# Modelo a usar. Debe estar CARGADO en LM Studio. Si hay varios cargados, el agente
# usa este exactamente (no adivina). Déjalo en None para tomar el primero disponible.
LM_MODEL  = "qwen2.5-14b-instruct-1m"     # Instruct puro, contexto 1M — ideal forense
LM_TEMP   = 0.1                            # temperatura baja → respuestas factuales
LM_MAXTOK = 2048   # modelo Instruct (no "thinking"): 2048 basta para una respuesta
                   # forense y acota el tiempo de generación en hardware modesto
LM_FREQ_PENALTY = 0.5   # penaliza tokens repetidos → evita loops de degeneración
LM_PRES_PENALTY = 0.3   # penaliza reincidir en lo mismo
LM_TIMEOUT = 1200  # segundos. Alto: un modelo denso de 14B tarda en procesar (prefill)
                   # prompts grandes y en generar la respuesta final en hardware modesto.

# Desactiva el "extended thinking" (soft-switch /no_think de Qwen3). qwen2.5-instruct
# NO es un modelo thinking, así que se deja en False (no necesita /no_think, que para
# este modelo sería solo texto basura en el prompt). Ponlo en True solo si vuelves a
# usar un modelo de la familia Qwen3 "thinking".
LM_DISABLE_THINKING = False

# Ruta a vol.py de Volatility 3 (relativa a este script)
VOL_PY = Path(__file__).parent.parent / "volatility3-2.28.0" / "volatility3-2.28.0" / "vol.py"

# Directorio de símbolos integrados de Volatility (generic + linux)
VOL_SYMBOLS = VOL_PY.parent / "volatility3" / "symbols"

MAX_LINES = 800   # líneas máximas por plugin. Suficiente para ver COMPLETOS psscan y
                  # netscan de un servidor típico sin truncar IPs externas, y liviano
                  # para el prefill del modelo. El contexto 1M da margen de sobra; el
                  # límite real es la velocidad de prefill, no la capacidad.
MAX_TURNS = 8     # iteraciones máximas del ReAct loop por pregunta
MAX_STALLS = 3    # turnos improductivos seguidos (sin plugin nuevo ni respuesta) → abortar

# Variables de caso — se asignan en setup_case() / select_os() al iniciar
_dump_file: Path | None = None
_isf_dir:   Path | None = None
_case_desc: str         = ""
_cache_dir: Path | None = None
_os_type:   str         = ""   # "linux" | "windows" | "macos"

# ═══════════════════════════════════════════════════════════════════════════════
#  PLUGINS PERMITIDOS  —  whitelist de seguridad
#  Solo estos pueden ejecutarse vía subprocess. Organizados por plataforma.
# ═══════════════════════════════════════════════════════════════════════════════

PLUGINS: dict[str, str] = {

    # ── LINUX ─────────────────────────────────────────────────────────────────

    "linux.bash.Bash":
        "[Linux] Historial de comandos bash en procesos activos (desde memoria)",
    "linux.boottime.Boottime":
        "[Linux] Tiempo de arranque del sistema",
    "linux.capabilities.Capabilities":
        "[Linux] Capacidades Linux (CAP_*) asignadas por proceso",
    "linux.check_afinfo.Check_afinfo":
        "[Linux] Integridad de estructuras afinfo de red (detección de rootkit)",
    "linux.check_creds.Check_creds":
        "[Linux] Procesos con credenciales UID/GID compartidas (indicio de rootkit)",
    "linux.check_idt.Check_idt":
        "[Linux] Integridad de la tabla de descriptores de interrupción (IDT)",
    "linux.check_modules.Check_modules":
        "[Linux] Módulos kernel: lsmod vs sysfs (detecta módulos ocultos)",
    "linux.check_syscall.Check_syscall":
        "[Linux] Integridad de la syscall table del kernel (detección de hooking)",
    "linux.ebpf.EBPF":
        "[Linux] Programas eBPF cargados en el kernel",
    "linux.elfs.Elfs":
        "[Linux] Archivos ELF mapeados en memoria por proceso",
    "linux.envars.Envars":
        "[Linux] Variables de entorno por proceso",
    "linux.hidden_modules.Hidden_modules":
        "[Linux] Módulos kernel ocultos (detección avanzada)",
    "linux.iomem.IOMem":
        "[Linux] Mapa de memoria de E/S (equivalente a /proc/iomem)",
    "linux.ip.Addr":
        "[Linux] Interfaces de red y direcciones IP configuradas",
    "linux.ip.Link":
        "[Linux] Información de interfaces de red (equivalente a ip link)",
    "linux.kallsyms.Kallsyms":
        "[Linux] Símbolos del kernel desde /proc/kallsyms en memoria",
    "linux.keyboard_notifiers.Keyboard_notifiers":
        "[Linux] Keyloggers a nivel kernel via keyboard notifiers",
    "linux.kmsg.Kmsg":
        "[Linux] Buffer del log del kernel (equivalente a dmesg)",
    "linux.kthreads.Kthreads":
        "[Linux] Hilos del kernel activos",
    "linux.library_list.LibraryList":
        "[Linux] Librerías (.so) cargadas por proceso",
    "linux.lsmod.Lsmod":
        "[Linux] Módulos del kernel cargados",
    "linux.lsof.Lsof":
        "[Linux] Archivos abiertos por proceso",
    "linux.malfind.Malfind":
        "[Linux] Regiones de memoria ejecutables sospechosas (shellcode/malware)",
    "linux.malware.check_afinfo.Check_afinfo":
        "[Linux/Malware] Integridad afinfo (variante de detección de malware)",
    "linux.malware.check_creds.Check_creds":
        "[Linux/Malware] Credenciales compartidas (variante malware)",
    "linux.malware.check_idt.Check_idt":
        "[Linux/Malware] Integridad IDT (variante malware)",
    "linux.malware.check_modules.Check_modules":
        "[Linux/Malware] Módulos ocultos (variante malware)",
    "linux.malware.check_syscall.Check_syscall":
        "[Linux/Malware] Syscall table hooking (variante malware)",
    "linux.malware.hidden_modules.Hidden_modules":
        "[Linux/Malware] Módulos kernel ocultos (variante malware avanzada)",
    "linux.malware.keyboard_notifiers.Keyboard_notifiers":
        "[Linux/Malware] Keyloggers kernel (variante malware)",
    "linux.malware.malfind.Malfind":
        "[Linux/Malware] Código inyectado en procesos (variante malware)",
    "linux.malware.modxview.Modxview":
        "[Linux/Malware] Vista cruzada de módulos kernel (múltiples fuentes)",
    "linux.malware.netfilter.Netfilter":
        "[Linux/Malware] Hooks maliciosos en netfilter/iptables",
    "linux.malware.process_spoofing.ProcessSpoofing":
        "[Linux/Malware] Detección de suplantación de procesos",
    "linux.malware.tty_check.Tty_Check":
        "[Linux/Malware] Hooks maliciosos en dispositivos TTY",
    "linux.modxview.Modxview":
        "[Linux] Vista cruzada de módulos: lsmod vs sysfs vs kobjects",
    "linux.mountinfo.MountInfo":
        "[Linux] Puntos de montaje del sistema de archivos",
    "linux.netfilter.Netfilter":
        "[Linux] Hooks registrados en netfilter/iptables",
    "linux.pagecache.Files":
        "[Linux] Archivos presentes en el page cache",
    "linux.pagecache.InodePages":
        "[Linux] Páginas de inodo en caché de memoria",
    "linux.pidhashtable.PIDHashTable":
        "[Linux] Procesos vía hash table de PIDs (detecta procesos ocultos)",
    "linux.proc.Maps":
        "[Linux] Mapas de memoria virtual por proceso (equivalente a /proc/PID/maps)",
    "linux.psaux.PsAux":
        "[Linux] Procesos con líneas de comando completas (argv)",
    "linux.pscallstack.PsCallStack":
        "[Linux] Call stack de procesos en memoria",
    "linux.pslist.PsList":
        "[Linux] Lista de procesos en memoria",
    "linux.psscan.PsScan":
        "[Linux] Escaneo de task_struct en memoria (detecta procesos ocultos)",
    "linux.pstree.PsTree":
        "[Linux] Árbol padre-hijo de procesos",
    "linux.ptrace.Ptrace":
        "[Linux] Procesos siendo trazados con ptrace (depuración/espionaje)",
    "linux.sockscan.Sockscan":
        "[Linux] Escaneo de sockets en memoria (detecta sockets ocultos)",
    "linux.sockstat.Sockstat":
        "[Linux] Conexiones y sockets de red activos (TCP/UDP/UNIX)",
    "linux.tracing.ftrace.CheckFtrace":
        "[Linux] Integridad de ftrace (hooks de tracing del kernel)",
    "linux.tracing.perf_events.PerfEvents":
        "[Linux] Eventos perf activos en memoria",
    "linux.tracing.tracepoints.CheckTracepoints":
        "[Linux] Integridad de tracepoints del kernel",
    "linux.tty_check.tty_check":
        "[Linux] Hooks en dispositivos TTY (keyloggers)",
    "linux.vmcoreinfo.VMCoreInfo":
        "[Linux] Información de vmcoreinfo embebida en el dump",

    # ── WINDOWS ───────────────────────────────────────────────────────────────

    "windows.amcache.Amcache":
        "[Windows] Programas ejecutados (AmCache del registro en memoria)",
    "windows.bigpools.BigPools":
        "[Windows] Grandes asignaciones en el pool de memoria del kernel",
    "windows.callbacks.Callbacks":
        "[Windows] Callbacks del kernel registrados (PsSetCreateProcessNotifyRoutine, etc.)",
    "windows.cmdline.CmdLine":
        "[Windows] Líneas de comando de procesos activos",
    "windows.cmdscan.CmdScan":
        "[Windows] Historial de comandos de consola (cmd.exe) desde memoria",
    "windows.consoles.Consoles":
        "[Windows] Buffers de consola en memoria",
    "windows.crashinfo.Crashinfo":
        "[Windows] Información de crash dump de Windows",
    "windows.debugregisters.DebugRegisters":
        "[Windows] Registros de depuración de hardware por proceso (breakpoints)",
    "windows.deskscan.DeskScan":
        "[Windows] Escaneo de objetos Desktop en pool de memoria",
    "windows.desktops.Desktops":
        "[Windows] Desktops y windowstations del sistema",
    "windows.devicetree.DeviceTree":
        "[Windows] Árbol de dispositivos del kernel (drivers/dispositivos)",
    "windows.dlllist.DllList":
        "[Windows] DLLs cargadas por proceso",
    "windows.driverirp.DriverIrp":
        "[Windows] Rutinas IRP de drivers (detección de hooking)",
    "windows.drivermodule.DriverModule":
        "[Windows] Drivers asociados a módulos del kernel",
    "windows.driverscan.DriverScan":
        "[Windows] Escaneo de objetos driver en pool de memoria",
    "windows.envars.Envars":
        "[Windows] Variables de entorno por proceso",
    "windows.etwpatch.EtwPatch":
        "[Windows] Detección de parches a ETW (evasión de logging de eventos)",
    "windows.filescan.FileScan":
        "[Windows] Escaneo de objetos FILE_OBJECT en pool de memoria",
    "windows.getservicesids.GetServiceSIDs":
        "[Windows] SIDs asociados a servicios de Windows",
    "windows.getsids.GetSIDs":
        "[Windows] SIDs por proceso (identidad y nivel de privilegio)",
    "windows.handles.Handles":
        "[Windows] Handles abiertos por proceso (archivos, claves de registro, etc.)",
    "windows.hollowprocesses.HollowProcesses":
        "[Windows] Detección de process hollowing",
    "windows.iat.IAT":
        "[Windows] Import Address Table por módulo (detección de API hooking)",
    "windows.info.Info":
        "[Windows] Información del OS y kernel del dump (versión, arquitectura)",
    "windows.joblinks.JobLinks":
        "[Windows] Objetos Job y procesos asociados",
    "windows.kpcrs.KPCRs":
        "[Windows] Kernel Processor Control Regions (una por CPU)",
    "windows.ldrmodules.LdrModules":
        "[Windows] Módulos en listas del loader por proceso (detección de DLLs ocultas)",
    "windows.malfind.Malfind":
        "[Windows] Regiones de memoria inyectadas (shellcode/DLL injection)",
    "windows.malware.drivermodule.DriverModule":
        "[Windows/Malware] Drivers sin módulo asociado (rootkits)",
    "windows.malware.hollowprocesses.HollowProcesses":
        "[Windows/Malware] Process hollowing avanzado",
    "windows.malware.ldrmodules.LdrModules":
        "[Windows/Malware] DLLs ocultas en listas del loader",
    "windows.malware.malfind.Malfind":
        "[Windows/Malware] Inyección de código avanzada",
    "windows.malware.pebmasquerade.PebMasquerade":
        "[Windows/Malware] Mascarada de PEB (proceso que oculta su nombre real)",
    "windows.malware.processghosting.ProcessGhosting":
        "[Windows/Malware] Process ghosting (evasión de AV/EDR)",
    "windows.malware.psxview.PsXView":
        "[Windows/Malware] Vista cruzada de procesos desde 6+ fuentes",
    "windows.malware.skeleton_key_check.Skeleton_Key_Check":
        "[Windows/Malware] Detección de skeleton key en LSASS",
    "windows.malware.suspicious_threads.SuspiciousThreads":
        "[Windows/Malware] Hilos sospechosos (inicio en región anónima/inyectada)",
    "windows.malware.svcdiff.SvcDiff":
        "[Windows/Malware] Servicios ocultos (SCM vs registro)",
    "windows.malware.unhooked_system_calls.UnhookedSystemCalls":
        "[Windows/Malware] Syscalls hooked vs no hooked",
    "windows.mbrscan.MBRScan":
        "[Windows] Escaneo de Master Boot Records en memoria",
    "windows.memmap.Memmap":
        "[Windows] Mapa de memoria virtual de un proceso",
    "windows.modscan.ModScan":
        "[Windows] Escaneo de LDR_DATA_TABLE_ENTRY en pool (módulos ocultos)",
    "windows.modules.Modules":
        "[Windows] Módulos del kernel cargados (lista desde PsLoadedModuleList)",
    "windows.mutantscan.MutantScan":
        "[Windows] Objetos mutex en memoria (indicadores de familia de malware)",
    "windows.netscan.NetScan":
        "[Windows] Escaneo de estructuras de red en pool (conexiones/sockets)",
    "windows.netstat.NetStat":
        "[Windows] Conexiones de red activas",
    "windows.orphan_kernel_threads.Threads":
        "[Windows] Hilos de kernel huérfanos (sin proceso asociado — rootkits)",
    "windows.poolscanner.PoolScanner":
        "[Windows] Escaneo genérico de objetos en pool de memoria",
    "windows.privileges.Privs":
        "[Windows] Privilegios habilitados/deshabilitados por proceso",
    "windows.processghosting.ProcessGhosting":
        "[Windows] Process ghosting (evasión de herramientas de seguridad)",
    "windows.pslist.PsList":
        "[Windows] Lista de procesos activos (desde PsActiveProcessHead)",
    "windows.psscan.PsScan":
        "[Windows] Escaneo de EPROCESS en pool (detecta procesos ocultos/terminados)",
    "windows.pstree.PsTree":
        "[Windows] Árbol de procesos con relaciones padre-hijo",
    "windows.psxview.PsXView":
        "[Windows] Vista cruzada de procesos desde múltiples fuentes",
    "windows.registry.amcache.Amcache":
        "[Windows] AmCache del registro (historial de ejecuciones)",
    "windows.registry.certificates.Certificates":
        "[Windows] Certificados almacenados en el registro",
    "windows.registry.hivelist.HiveList":
        "[Windows] Hives del registro cargados en memoria",
    "windows.registry.hivescan.HiveScan":
        "[Windows] Escaneo de hives en pool de memoria",
    "windows.registry.scheduled_tasks.ScheduledTasks":
        "[Windows] Tareas programadas desde el registro en memoria",
    "windows.registry.userassist.UserAssist":
        "[Windows] UserAssist: programas ejecutados desde el explorador",
    "windows.scheduled_tasks.ScheduledTasks":
        "[Windows] Tareas programadas desde estructuras en memoria",
    "windows.sessions.Sessions":
        "[Windows] Sesiones de usuario activas en memoria",
    "windows.shimcachemem.ShimcacheMem":
        "[Windows] Shim Cache (Application Compatibility Cache) en memoria",
    "windows.skeleton_key_check.Skeleton_Key_Check":
        "[Windows] Skeleton key en LSASS (credencial universal maliciosa)",
    "windows.ssdt.SSDT":
        "[Windows] System Service Descriptor Table (detección de hooking de syscalls)",
    "windows.statistics.Statistics":
        "[Windows] Estadísticas del dump (páginas presentes/ausentes)",
    "windows.suspended_threads.SuspendedThreads":
        "[Windows] Hilos suspendidos (posible evasión de análisis)",
    "windows.suspicious_threads.SuspiciousThreads":
        "[Windows] Hilos sospechosos en procesos",
    "windows.svcdiff.SvcDiff":
        "[Windows] Diferencia entre servicios en SCM vs registro (detecta ocultos)",
    "windows.svclist.SvcList":
        "[Windows] Lista de servicios desde SCM en memoria",
    "windows.svcscan.SvcScan":
        "[Windows] Escaneo de estructuras de servicio en pool",
    "windows.symlinkscan.SymlinkScan":
        "[Windows] Objetos symlink en pool de memoria",
    "windows.thrdscan.ThrdScan":
        "[Windows] Escaneo de ETHREAD en pool de memoria",
    "windows.threads.Threads":
        "[Windows] Hilos por proceso con información de contexto",
    "windows.timers.Timers":
        "[Windows] Timers del kernel (usados por rootkits para persistencia)",
    "windows.truecrypt.Passphrase":
        "[Windows] Passphrase de TrueCrypt/VeraCrypt en memoria",
    "windows.unhooked_system_calls.unhooked_system_calls":
        "[Windows] Syscalls sin hooking (baseline para comparación)",
    "windows.unloadedmodules.UnloadedModules":
        "[Windows] Módulos del kernel descargados recientemente",
    "windows.vadinfo.VadInfo":
        "[Windows] Virtual Address Descriptors por proceso (mapa VAD)",
    "windows.vadwalk.VadWalk":
        "[Windows] Recorrido del árbol VAD por proceso",
    "windows.verinfo.VerInfo":
        "[Windows] Información de versión de módulos PE en memoria",
    "windows.virtmap.VirtMap":
        "[Windows] Mapa de memoria virtual del sistema",
    "windows.windows.Windows":
        "[Windows] Objetos ventana en memoria (GUI)",
    "windows.windowstations.WindowStations":
        "[Windows] WindowStations del sistema",

    # ── macOS ─────────────────────────────────────────────────────────────────

    "mac.bash.Bash":
        "[macOS] Historial de comandos bash en memoria",
    "mac.check_syscall.Check_syscall":
        "[macOS] Integridad de la syscall table",
    "mac.check_sysctl.Check_sysctl":
        "[macOS] Integridad de los handlers sysctl",
    "mac.check_trap_table.Check_trap_table":
        "[macOS] Integridad de la mach trap table",
    "mac.dmesg.Dmesg":
        "[macOS] Log del kernel (dmesg)",
    "mac.ifconfig.Ifconfig":
        "[macOS] Interfaces de red y configuración",
    "mac.kauth_listeners.Kauth_listeners":
        "[macOS] Listeners kauth registrados",
    "mac.kauth_scopes.Kauth_scopes":
        "[macOS] Scopes kauth del kernel",
    "mac.kevents.Kevents":
        "[macOS] Kevents activos por proceso",
    "mac.list_files.List_Files":
        "[macOS] Archivos abiertos en el sistema",
    "mac.lsmod.Lsmod":
        "[macOS] Módulos del kernel (kexts) cargados",
    "mac.lsof.Lsof":
        "[macOS] Archivos abiertos por proceso",
    "mac.malfind.Malfind":
        "[macOS] Regiones de memoria sospechosas (malware)",
    "mac.netstat.Netstat":
        "[macOS] Conexiones de red activas",
    "mac.proc_maps.Maps":
        "[macOS] Mapas de memoria de procesos",
    "mac.psaux.Psaux":
        "[macOS] Procesos con argumentos de línea de comandos",
    "mac.pslist.PsList":
        "[macOS] Lista de procesos",
    "mac.pstree.PsTree":
        "[macOS] Árbol de procesos",
    "mac.socket_filters.Socket_filters":
        "[macOS] Filtros de socket registrados",
    "mac.timers.Timers":
        "[macOS] Timers del kernel (rootkits)",
    "mac.trustedbsd.Trustedbsd":
        "[macOS] Políticas TrustedBSD activas",
    "mac.vfsevents.VFSevents":
        "[macOS] Listeners de eventos VFS",

    # ── CROSS-PLATFORM ────────────────────────────────────────────────────────

    "banners.Banners":
        "[Universal] Identificación del OS por strings/banners en memoria",
    "isfinfo.IsfInfo":
        "[Universal] Información sobre archivos ISF de símbolos disponibles",
    "timeliner.Timeliner":
        "[Universal] Línea de tiempo de artefactos forenses",
    "frameworkinfo.FrameworkInfo":
        "[Universal] Información del framework Volatility 3",
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PROMPT DEL SISTEMA
# ═══════════════════════════════════════════════════════════════════════════════

_OS_LABELS = {
    "linux":   "Linux",
    "windows": "Windows",
    "macos":   "macOS",
}

# Guía rápida intención → plugin EXACTO. Es la principal defensa anti-alucinación:
# el modelo copia el nombre de aquí en vez de inventarlo.
_OS_GUIDE = {
    "windows": """\
GUÍA DE SELECCIÓN (Windows) — copia estos nombres EXACTOS, no los modifiques:
  - Procesos en ejecución       → windows.psscan.PsScan
  - Árbol de procesos           → windows.pstree.PsTree
  - Líneas de comando (argv)    → windows.cmdline.CmdLine
  - Conexiones de red / IPs     → windows.netscan.NetScan
  - DLLs cargadas por proceso   → windows.dlllist.DllList
  - Servicios                   → windows.svcscan.SvcScan
  - Inyección de código         → windows.malfind.Malfind
  - Info del SO / build         → windows.info.Info
  NOTA: para procesos y red usa las variantes de ESCANEO (psscan/netscan):
  funcionan aunque el recorrido de listas enlazadas falle y además detectan
  procesos/conexiones ocultos o ya terminados. pslist/netstat pueden devolver
  vacío en algunos dumps.
""",
    "linux": """\
GUÍA DE SELECCIÓN (Linux) — copia estos nombres EXACTOS, no los modifiques:
  - Procesos en ejecución       → linux.pslist.PsList
  - Procesos con argumentos     → linux.psaux.PsAux
  - Árbol de procesos           → linux.pstree.PsTree
  - Conexiones de red / IPs     → linux.sockstat.Sockstat
  - Módulos del kernel          → linux.lsmod.Lsmod
  - Historial bash              → linux.bash.Bash
  - Inyección de código         → linux.malfind.Malfind
  NOTA: si un plugin de lista devuelve vacío, usa la variante de escaneo:
  linux.psscan.PsScan (procesos) o linux.sockscan.Sockscan (red).
""",
    "macos": """\
GUÍA DE SELECCIÓN (macOS) — copia estos nombres EXACTOS, no los modifiques:
  - Procesos en ejecución       → mac.pslist.PsList
  - Procesos con argumentos     → mac.psaux.Psaux
  - Árbol de procesos           → mac.pstree.PsTree
  - Conexiones de red / IPs     → mac.netstat.Netstat
  - Módulos (kexts)             → mac.lsmod.Lsmod
""",
}

_SYSTEM_TEMPLATE = """\
Eres un agente de análisis forense de memoria RAM para investigación de \
incidentes de ciberseguridad. Trabajas con un investigador humano de \
la consultora GLOBALSECURE.

DUMP EN ANÁLISIS:
  - Archivo          : {dump_name}
  - Tamaño           : {dump_size}
  - Sistema operativo: {os_label}
{case_block}\
HERRAMIENTA: Volatility 3 (vol.py)

USA ÚNICAMENTE los plugins listados abajo — son los correspondientes a {os_label} \
más los universales. No intentes plugins de otras plataformas.

REGLAS ABSOLUTAS — nunca las violes:
  1. JAMÁS inventes ni supongas datos. Si no aparece en el output real de un
     plugin, NO EXISTE para ti.
  2. NUNCA menciones PIDs, procesos, IPs, comandos, módulos, dominios ni
     timestamps que no hayas leído TEXTUALMENTE en el output recibido.
     EN PARTICULAR: el output de red contiene SOLO direcciones IP numéricas,
     NUNCA nombres de dominio. JAMÁS conviertas una IP a un dominio, ni nombres
     servicios/empresas por conocimiento propio (nada de "microsoft.com",
     "googleapis.com", "AWS", etc. salvo que aparezca LITERAL en el output).
     No enriquezcas, no resuelvas, no interpretes con conocimiento externo.
  3. Si no tienes evidencia suficiente di exactamente:
     "No hay evidencia en el dump para responder esa pregunta."
  4. Cita siempre qué plugin produjo cada dato que menciones en tu respuesta.
  5. Si un plugin falla o devuelve vacío, repórtalo explícitamente.
  6. No uses datos de respuestas anteriores a menos que hayas visto el output
     del plugin en esta misma sesión.

REGLAS DE EFICIENCIA — para no perder tiempo:
  7. Sé BREVE y directo. NO razones extensamente. En cada turno emite de
     inmediato UNA sola línea: o RUN_PLUGIN: o FINAL_ANSWER:. Nada más.
  8. Usa SOLO nombres de plugin que aparezcan literalmente en la GUÍA o en la
     lista de abajo. Si el nombre no está ahí, NO existe. Nunca lo inventes.
  9. NUNCA ejecutes dos veces el mismo plugin: su output ya está en el hilo.
 10. Responde con FINAL_ANSWER apenas tengas los datos. La mayoría de preguntas
     se resuelven con 1 o 2 plugins. No ejecutes plugins de más.

{os_guide}
PROCESO DE TRABAJO (ReAct):
  1. Lee la pregunta del investigador.
  2. Elige el plugin de {os_label} desde la GUÍA de arriba.
  3. Ejecútalo con el formato exacto (RUN_PLUGIN:).
  4. Lee el output REAL. Si te falta un dato, ejecuta OTRO plugin (distinto).
  5. Responde con FINAL_ANSWER en cuanto tengas evidencia suficiente.

PLUGINS DISPONIBLES ({plugin_count} para {os_label} + universales):
{plugin_list}

FORMATO DE RESPUESTA — usa EXCLUSIVAMENTE estos dos formatos, una línea:

Para ejecutar un plugin (una sola línea exacta, sin comillas):
  RUN_PLUGIN: {example_plugin}

Para responder al investigador (solo cuando tengas evidencia real):
  FINAL_ANSWER: [respuesta basada en evidencia, citando plugin y datos exactos]

Nota: si la pregunta es sobre el agente en sí (no requiere Volatility),
responde directamente con FINAL_ANSWER sin ejecutar plugins.
"""

# Prefijos de plugins por OS (para filtrar el listado en el system prompt)
_OS_PREFIXES = {
    "linux":   ("linux.",),
    "windows": ("windows.",),
    "macos":   ("mac.",),
}
# Plugins universales siempre incluidos
_UNIVERSAL_PREFIXES = ("banners.", "isfinfo.", "timeliner.", "frameworkinfo.")


def _plugins_for_os() -> dict[str, str]:
    """Devuelve solo los plugins del OS seleccionado + universales."""
    prefixes = _OS_PREFIXES.get(_os_type, ())
    return {
        k: v for k, v in PLUGINS.items()
        if any(k.startswith(p) for p in prefixes + _UNIVERSAL_PREFIXES)
    }


_OS_EXAMPLE = {
    "linux":   "linux.pslist.PsList",
    "windows": "windows.psscan.PsScan",
    "macos":   "mac.pslist.PsList",
}


def build_system_prompt() -> str:
    assert _dump_file is not None and _os_type
    active_plugins = _plugins_for_os()
    plugin_list = "\n".join(f"  - {k}: {v}" for k, v in active_plugins.items())
    size_gb = _dump_file.stat().st_size / 1e9
    case_block = f"  - Contexto: {_case_desc}\n" if _case_desc else ""
    prompt = _SYSTEM_TEMPLATE.format(
        dump_name=_dump_file.name,
        dump_size=f"{size_gb:.2f} GB",
        os_label=_OS_LABELS[_os_type],
        os_guide=_OS_GUIDE.get(_os_type, ""),
        example_plugin=_OS_EXAMPLE.get(_os_type, "windows.pslist.PsList"),
        case_block=case_block,
        plugin_count=len(active_plugins),
        plugin_list=plugin_list,
    )
    if LM_DISABLE_THINKING:
        # Soft-switch de Qwen3: desactiva el razonamiento extendido para acelerar.
        prompt += "\n/no_think"
    return prompt


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURACIÓN DE CASO  —  se ejecuta al inicio interactivo
# ═══════════════════════════════════════════════════════════════════════════════

def setup_case() -> None:
    """Pide al analista los datos del caso: dump, ISF adicional, descripción."""
    global _dump_file, _isf_dir, _case_desc, _cache_dir

    print("\n─── CONFIGURACIÓN DEL CASO ───────────────────────────────────────")

    # ── Ruta al dump ──────────────────────────────────────────────────────────
    while True:
        raw = input("Ruta al dump de memoria (.lime / .raw / .vmem / .dmp): ").lstrip("﻿").strip().strip('"')
        if not raw:
            print("  La ruta no puede estar vacía.")
            continue
        p = Path(raw)
        if not p.exists():
            print(f"  [ERROR] No existe: {p}")
            continue
        if not p.is_file():
            print(f"  [ERROR] No es un archivo: {p}")
            continue
        size_gb = p.stat().st_size / 1e9
        print(f"  [OK] {p.name}  ({size_gb:.2f} GB)")
        _dump_file = p
        break

    # ── Directorio de símbolos ISF adicional ──────────────────────────────────
    print(f"  [OK] Símbolos integrados de Volatility: {VOL_SYMBOLS}")
    print( "       (Para kernel custom como Oracle UEK, RHEL específico, etc.,")
    print( "        proporciona un directorio adicional con el .json generado")
    print( "        por dwarf2json. Si usas un kernel estándar, presiona Enter.)")
    raw_isf = input("Directorio ISF adicional (Enter para omitir): ").strip().strip('"')

    if raw_isf:
        _isf_dir = Path(raw_isf)
        if not _isf_dir.exists():
            print(f"  [AVISO] No encontrado: {_isf_dir} — Volatility puede fallar.")
        else:
            jsons = list(_isf_dir.glob("*.json"))
            if jsons:
                print(f"  [OK] ISF adicional: {_isf_dir}  ({len(jsons)} .json)")
            else:
                print(f"  [AVISO] {_isf_dir} no tiene .json — Volatility puede fallar.")
    else:
        _isf_dir = None
        print("  Sin ISF adicional — se usarán solo los símbolos integrados.")

    # ── Descripción opcional del caso ─────────────────────────────────────────
    _case_desc = input("Descripción breve del caso (opcional, Enter para omitir): ").strip()

    # ── Caché por caso (hash de la ruta del dump) ─────────────────────────────
    dump_hash = hashlib.md5(str(_dump_file).encode()).hexdigest()[:8]
    _cache_dir = Path(__file__).parent / "cache" / dump_hash
    _cache_dir.mkdir(parents=True, exist_ok=True)
    print(f"  [OK] Caché del caso: {_cache_dir}")
    print("──────────────────────────────────────────────────────────────────")


# ═══════════════════════════════════════════════════════════════════════════════
#  IDENTIFICACIÓN DE SISTEMA OPERATIVO  —  se ejecuta tras setup_case()
# ═══════════════════════════════════════════════════════════════════════════════

def select_os() -> None:
    """Pregunta al analista qué sistema operativo tiene el dump a analizar."""
    global _os_type

    opciones = {
        "1": ("linux",   "Linux"),
        "2": ("windows", "Windows"),
        "3": ("macos",   "macOS"),
    }

    print("\n─── SISTEMA OPERATIVO DEL DUMP ───────────────────────────────────")
    print("  ¿Qué sistema operativo corresponde al dump de memoria?")
    print()
    for num, (_, label) in opciones.items():
        print(f"    [{num}] {label}")
    print()

    while True:
        resp = input("  Selección (1/2/3): ").strip()
        if resp in opciones:
            _os_type, label = opciones[resp]
            print(f"  [OK] Sistema operativo: {label}")
            break
        print("  Ingresa 1, 2 o 3.")

    print("──────────────────────────────────────────────────────────────────")


# ═══════════════════════════════════════════════════════════════════════════════
#  LM STUDIO  —  conexión y llamadas
# ═══════════════════════════════════════════════════════════════════════════════

def check_lmstudio() -> tuple[str | None, str | None]:
    """Verifica la conexión con LM Studio. Retorna (model_id, None) o (None, error)."""
    try:
        r = requests.get(f"{LM_BASE}/v1/models", timeout=8)
        r.raise_for_status()
        models = r.json().get("data", [])
        if not models:
            return None, "LM Studio responde pero no tiene ningún modelo cargado."
        ids = [m["id"] for m in models]

        # Si se fijó un modelo, exigir que esté cargado (no adivinar entre varios).
        if LM_MODEL:
            if LM_MODEL in ids:
                return LM_MODEL, None
            return None, (
                f"El modelo configurado '{LM_MODEL}' no está cargado en LM Studio.\n"
                f"  Modelos cargados: {', '.join(ids)}\n"
                f"  — Cárgalo en LM Studio, o ajusta LM_MODEL en la config del script."
            )

        # Sin modelo fijado: usar el primero disponible.
        return ids[0], None
    except requests.exceptions.ConnectionError:
        return None, (
            f"No se puede conectar a {LM_BASE}\n"
            "  — Verifica que LM Studio esté corriendo y el servidor local activo."
        )
    except requests.exceptions.Timeout:
        return None, f"Timeout al conectar con {LM_BASE} (>8 s)."
    except Exception as e:
        return None, f"Error inesperado: {e}"


def llm_call(messages: list[dict], model: str) -> str:
    """Envía mensajes a LM Studio. Retorna el texto del asistente."""
    r = requests.post(
        f"{LM_BASE}/v1/chat/completions",
        json={
            "model":             model,
            "messages":          messages,
            "temperature":       LM_TEMP,
            "max_tokens":        LM_MAXTOK,
            "frequency_penalty": LM_FREQ_PENALTY,
            "presence_penalty":  LM_PRES_PENALTY,
            "stream":            False,
        },
        timeout=LM_TIMEOUT,
    )
    r.raise_for_status()
    msg = r.json()["choices"][0]["message"]
    content = (msg.get("content") or "").strip()
    if content:
        return content
    # Qwen3 thinking: cuando max_tokens es insuficiente, content queda vacío y el
    # razonamiento va en reasoning_content — lo envolvemos en <think> para que
    # strip_thinking() lo descarte sin contaminar el parsing del agente.
    reasoning = (msg.get("reasoning_content") or "").strip()
    return f"<think>{reasoning}</think>" if reasoning else ""


# ═══════════════════════════════════════════════════════════════════════════════
#  VOLATILITY  —  ejecución y caché
# ═══════════════════════════════════════════════════════════════════════════════

def run_volatility(plugin: str) -> str:
    """
    Ejecuta un plugin de Volatility 3 contra el dump del caso.
    - Solo acepta plugins de PLUGINS (whitelist de seguridad).
    - Siempre incluye los símbolos integrados de Volatility.
    - Si hay ISF adicional, lo agrega como segundo directorio de símbolos.
    - Cachea los resultados para no re-ejecutar durante la sesión.
    - Trunca a MAX_LINES para no desbordar el contexto del LLM.
    """
    assert _dump_file is not None and _cache_dir is not None

    if plugin not in PLUGINS:
        # Red de seguridad: run_agent ya valida el nombre antes de llegar aquí.
        return f"[ERROR] Plugin '{plugin}' no está permitido."

    slug      = plugin.replace(".", "_")
    cache_key = hashlib.md5(plugin.encode()).hexdigest()[:8]
    cache_f   = _cache_dir / f"{slug}_{cache_key}.txt"

    if cache_f.exists():
        print("    [desde caché]", flush=True)
        return cache_f.read_text(encoding="utf-8", errors="replace")

    # Construir lista de directorios de símbolos
    symbol_dirs = [str(VOL_SYMBOLS)]
    if _isf_dir is not None:
        symbol_dirs.append(str(_isf_dir))

    cmd = [
        sys.executable,
        str(VOL_PY),
        "-f", str(_dump_file),
        "--symbol-dirs", *symbol_dirs,
        plugin,
    ]
    print(f"    [ejecutando: vol.py {plugin}]", flush=True)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=400,
            cwd=str(_dump_file.parent),
            encoding="utf-8",
            errors="replace",
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        lines = stdout.splitlines()
        if len(lines) > MAX_LINES:
            out = "\n".join(lines[:MAX_LINES])
            out += (
                f"\n\n[TRUNCADO: {len(lines)} líneas totales — "
                f"mostrando las primeras {MAX_LINES}.]"
            )
        else:
            out = stdout

        if not out.strip():
            out = (
                f"(sin resultados en stdout)\nSTDERR:\n{stderr[:1200]}"
                if stderr else "(el plugin no retornó resultados)"
            )

        cache_f.write_text(out, encoding="utf-8")
        return out

    except subprocess.TimeoutExpired:
        return f"[ERROR] {plugin} excedió el tiempo límite (400 s)."
    except FileNotFoundError:
        return f"[ERROR] No se encontró vol.py en: {VOL_PY}"
    except Exception as e:
        return f"[ERROR] {type(e).__name__}: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
#  PARSEO DE RESPUESTAS DEL LLM
# ═══════════════════════════════════════════════════════════════════════════════

def strip_thinking(text: str) -> str:
    """Elimina bloques <think>…</think> que genera Qwen3 en modo razonamiento."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def is_degenerate(text: str) -> bool:
    """
    Detecta salidas degeneradas (loops de repetición típicos de modelos muy
    cuantizados), p.ej. 'usrwin.exe, usrwin.exe, usrwin.exe...' cientos de veces.
    True si un mismo token domina el texto de forma anómala.
    """
    tokens = re.findall(r"\S+", text)
    if len(tokens) < 30:
        return False
    from collections import Counter
    _, top = Counter(tokens).most_common(1)[0]
    return top / len(tokens) > 0.30


# TLDs reales para distinguir dominios inventados de nombres de plugin/proceso
# (windows.netscan.NetScan, svchost.exe, etc. NO terminan en un TLD real).
_REAL_TLDS = {
    "com", "net", "org", "io", "gov", "edu", "mil", "info", "biz", "co", "cl",
    "ar", "br", "ru", "cn", "uk", "de", "fr", "es", "mx", "us", "tv", "me",
    "app", "dev", "xyz", "online", "site", "cloud", "ai", "pe", "ve", "bo", "uy",
}


def verify_answer(answer: str, evidence: str) -> list[str]:
    """
    Cruza la respuesta del modelo contra la evidencia recolectada.
    Devuelve las IPs y dominios citados que NO aparecen textualmente en la
    evidencia → posibles alucinaciones (ej. el modelo inventa "microsoft.com"
    cuando netscan solo trae IPs). Es la red anti-alucinación de última línea.
    """
    suspects: set[str] = set()

    # IPv4 citadas que no están en la evidencia
    for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", answer)):
        if ip not in evidence:
            suspects.add(ip)

    # Dominios citados (que terminan en un TLD real) que no están en la evidencia
    for dom in set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b", answer)):
        tld = dom.rsplit(".", 1)[-1].lower()
        if tld in _REAL_TLDS and dom not in evidence:
            suspects.add(dom)

    return sorted(suspects)


def finalize_answer(answer: str, evidence_pool: list[str]) -> str:
    """
    Adjunta a la respuesta un aviso si contiene IPs/dominios que no aparecen en
    la evidencia recolectada. El investigador ve la respuesta del modelo Y, por
    separado, qué datos NO están respaldados por Volatility.
    """
    suspects = verify_answer(answer, "\n".join(evidence_pool))
    if suspects:
        answer += (
            "\n\n" + "⚠ " * 12 + "\n"
            "VERIFICACIÓN AUTOMÁTICA (anti-alucinación):\n"
            "Los siguientes datos citados en la respuesta NO aparecen textualmente "
            "en la evidencia extraída por Volatility y podrían ser INVENTADOS por el "
            "modelo. NO los uses sin confirmarlos manualmente en el output crudo:\n"
            + "\n".join(f"   • {s}" for s in suspects)
        )
    return answer


def parse_llm_response(raw: str) -> tuple[str, str]:
    """
    Parsea la respuesta del LLM.
    Retorna ("plugin", nombre), ("answer", texto) o ("raw", texto).
    """
    text = strip_thinking(raw)

    m = re.search(r"RUN_PLUGIN:\s*([\w.]+)", text)
    if m:
        return "plugin", m.group(1).strip()

    m = re.search(r"FINAL_ANSWER:\s*(.*)", text, re.DOTALL)
    if m:
        return "answer", m.group(1).strip()

    return "raw", text


def suggest_plugin(name: str) -> str | None:
    """
    Sugiere el plugin válido (del OS activo) más parecido a un nombre alucinado.
    Ej: 'windows.processes.SuspendedThreads' → 'windows.suspended_threads.SuspendedThreads'.
    """
    active = list(_plugins_for_os().keys())

    # 1) Coincidencia por el último componente (el "leaf", p.ej. SuspendedThreads)
    leaf = name.split(".")[-1].lower()
    leaf_hits = [k for k in active if k.split(".")[-1].lower() == leaf]
    if len(leaf_hits) == 1:
        return leaf_hits[0]

    # 2) Similitud difusa sobre el nombre completo
    matches = difflib.get_close_matches(name, active, n=1, cutoff=0.5)
    return matches[0] if matches else None


# Plugins de "lista enlazada" → su variante de "escaneo de pool", que funciona
# aunque el walk de la lista falle (visto en dumps reales: pslist vacío / psscan OK).
_FALLBACK: dict[str, str] = {
    "windows.pslist.PsList":     "windows.psscan.PsScan",
    "windows.netstat.NetStat":   "windows.netscan.NetScan",
    "windows.modules.Modules":   "windows.modscan.ModScan",
    "linux.pslist.PsList":       "linux.psscan.PsScan",
    "linux.sockstat.Sockstat":   "linux.sockscan.Sockscan",
}


def output_is_empty(output: str) -> bool:
    """
    True si el output de Volatility no tiene filas de datos reales
    (solo el banner del framework y la fila de encabezados de columnas).
    """
    if output.startswith("[ERROR]") or output.startswith("(sin resultados"):
        return True
    data_lines = [
        l for l in output.splitlines()
        if l.strip() and not l.startswith("Volatility 3 Framework")
    ]
    # Queda como mucho la fila de encabezados de columnas → sin datos.
    return len(data_lines) <= 1


def run_with_fallback(plugin: str, plugins_run: list[str]) -> str:
    """
    Ejecuta un plugin y, si devuelve vacío y tiene variante de escaneo definida
    en _FALLBACK, la ejecuta automáticamente (sin depender del modelo, que en
    local suele ignorar las correcciones). Registra en plugins_run lo ejecutado.
    """
    print(f"  [volatility: {plugin}]", flush=True)
    output = run_volatility(plugin)
    plugins_run.append(plugin)

    fb = _FALLBACK.get(plugin)
    if fb and fb not in plugins_run and output_is_empty(output):
        print(f"  [output vacío → autoejecutando {fb}]", flush=True)
        fb_out = run_volatility(fb)
        plugins_run.append(fb)
        output = (
            f"(NOTA: {plugin} no devolvió filas en este dump — el recorrido de "
            f"listas enlazadas falló. Se ejecutó automáticamente la variante de "
            f"escaneo de pool {fb}, cuyo resultado es el siguiente.)\n\n"
            f"{fb_out}"
        )
    return output


# ═══════════════════════════════════════════════════════════════════════════════
#  AGENTE REACT  —  loop principal por pregunta
# ═══════════════════════════════════════════════════════════════════════════════

def run_agent(question: str, model: str, history: list[dict]) -> str:
    """Loop ReAct: el LLM decide qué plugins ejecutar y luego responde."""
    messages: list[dict] = [
        {"role": "system", "content": build_system_prompt()}
    ]

    for h in history[-4:]:
        messages.append({"role": "user",      "content": h["q"]})
        messages.append({"role": "assistant", "content": h["a"]})

    messages.append({"role": "user", "content": question})

    plugins_run: list[str] = []
    evidence_pool: list[str] = []   # todos los outputs reales de plugins de esta pregunta
    stalls = 0   # turnos improductivos seguidos (sin plugin nuevo ni respuesta)

    for turn in range(MAX_TURNS):
        print(f"  [turno {turn + 1}/{MAX_TURNS} — consultando modelo...]", flush=True)

        try:
            raw = llm_call(messages, model)
        except requests.exceptions.Timeout:
            return f"[ERROR] LM Studio no respondió en {LM_TIMEOUT} s."
        except Exception as e:
            return f"[ERROR LM Studio] {e}"

        action, data = parse_llm_response(raw)

        # ── El modelo quiere ejecutar un plugin ───────────────────────────────
        if action == "plugin":
            requested = data
            # Resolver el nombre: si no es exacto, autocorregir al más parecido.
            resolved = requested if requested in PLUGINS else suggest_plugin(requested)

            # (a) No se pudo resolver a un plugin válido → pedir nombre correcto
            if resolved is None:
                stalls += 1
                print(f"  [nombre inválido, sin sugerencia: {requested}]", flush=True)
                messages.append({"role": "assistant", "content": f"RUN_PLUGIN: {requested}"})
                messages.append({"role": "user", "content": (
                    f"El plugin '{requested}' NO existe. Revisa la GUÍA DE SELECCIÓN "
                    "del prompt y responde con UNA línea 'RUN_PLUGIN: <nombre exacto>'."
                )})

            # (b) Resuelto a un plugin ya ejecutado → empujar a responder
            elif resolved in plugins_run:
                stalls += 1
                print(f"  [repetido, se omite: {resolved}]", flush=True)
                messages.append({"role": "assistant", "content": f"RUN_PLUGIN: {resolved}"})
                messages.append({"role": "user", "content": (
                    f"Ya ejecutaste '{resolved}' y su output está más arriba en el hilo. "
                    "NO lo repitas. Con los datos que ya tienes responde ahora con "
                    "FINAL_ANSWER:, o ejecuta un plugin DISTINTO si te falta evidencia."
                )})

            # (c) Plugin válido y nuevo → autocorregir (si hace falta) y ejecutar
            else:
                stalls = 0
                if resolved != requested:
                    print(f"  [autocorregido: {requested} → {resolved}]", flush=True)
                output = run_with_fallback(resolved, plugins_run)
                evidence_pool.append(output)
                messages.append({"role": "assistant", "content": f"RUN_PLUGIN: {resolved}"})
                messages.append({"role": "user", "content": (
                    f"RESULTADO DEL PLUGIN {resolved}:\n"
                    f"{'─' * 60}\n{output}\n{'─' * 60}\n\n"
                    "Analiza este output y responde con FINAL_ANSWER: "
                    "o ejecuta otro plugin DISTINTO si necesitas más evidencia."
                )})

        # ── El modelo da su respuesta final ───────────────────────────────────
        elif action == "answer":
            if is_degenerate(data):
                stalls += 1
                print("  [respuesta degenerada (loop de repetición), se descarta]", flush=True)
                messages.append({"role": "assistant", "content": "(respuesta descartada)"})
                messages.append({"role": "user", "content": (
                    "Tu respuesta entró en un loop de repetición y fue descartada. "
                    "Responde de forma BREVE y factual: enumera solo los datos reales "
                    "del output, sin repetir. Una línea 'FINAL_ANSWER: ...' concisa."
                )})
            else:
                return finalize_answer(data, evidence_pool)

        # ── Respuesta sin formato reconocible ─────────────────────────────────
        else:
            stalls += 1
            # Texto libre sustancial y NO degenerado → tratarlo como respuesta final
            if len(data.strip()) > 120 and not is_degenerate(data):
                return finalize_answer(data, evidence_pool)

            if not data.strip():
                # content vacío: el modelo gastó el presupuesto razonando
                print("  [respuesta vacía del modelo]", flush=True)
                nudge = (
                    "Tu respuesta llegó vacía (gastaste el presupuesto razonando). "
                    "NO razones. Emite YA una única línea, empezando por "
                    "'RUN_PLUGIN:' o 'FINAL_ANSWER:'."
                )
            else:
                nudge = (
                    "Formato no reconocido. Emite UNA línea que empiece por "
                    "'RUN_PLUGIN:' o 'FINAL_ANSWER:'."
                )
            messages.append({"role": "assistant", "content": raw or "(vacío)"})
            messages.append({"role": "user", "content": nudge})

        # ── Guardia de estancamiento ──────────────────────────────────────────
        if stalls >= MAX_STALLS:
            plugins_str = ", ".join(plugins_run) if plugins_run else "ninguno"
            return (
                f"[El modelo se estancó tras {stalls} turnos improductivos "
                "(nombres inválidos, repeticiones o respuestas vacías).]\n"
                f"Plugins con datos válidos obtenidos: {plugins_str}\n"
                "Sugerencia: reformula la pregunta de forma más concreta, o pide "
                "un plugin específico (ej.: 'ejecuta windows.pslist.PsList')."
            )

    plugins_str = ", ".join(plugins_run) if plugins_run else "ninguno"
    return (
        f"[Se alcanzó el límite de {MAX_TURNS} iteraciones sin respuesta final.]\n"
        f"Plugins ejecutados: {plugins_str}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN  —  interfaz de terminal
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║          AGENTE FORENSE DE RAM  —  GLOBALSECURE                  ║
║          Volatility 3  +  LM Studio  (análisis sin conexión)     ║
║          Linux  |  Windows  |  macOS                             ║
╚══════════════════════════════════════════════════════════════════╝"""

AYUDA = """
Comandos disponibles:
  plugins       — lista los plugins de Volatility autorizados
  cache clear   — borra resultados cacheados del caso actual
  historial     — muestra las preguntas realizadas en esta sesión
  salir         — termina la sesión

Cualquier otra entrada se envía al agente como pregunta forense.
El agente ejecutará los plugins necesarios y responderá solo con
evidencia real extraída del dump de memoria.
"""


def clear_cache() -> int:
    assert _cache_dir is not None
    removed = 0
    for f in _cache_dir.glob("*.txt"):
        f.unlink()
        removed += 1
    return removed


def main() -> None:
    print(BANNER)

    # ── Verificar vol.py ──────────────────────────────────────────────────────
    if not VOL_PY.exists():
        print(f"\n[ERROR] vol.py no encontrado en: {VOL_PY}")
        print("  Ajusta la variable VOL_PY en la sección CONFIGURACIÓN DE HERRAMIENTA.")
        sys.exit(1)
    print(f"\n  [OK] Volatility: {VOL_PY}")

    if not VOL_SYMBOLS.exists():
        print(f"  [AVISO] Directorio de símbolos integrados no encontrado: {VOL_SYMBOLS}")
    else:
        subdirs = [d.name for d in VOL_SYMBOLS.iterdir() if d.is_dir() and not d.name.startswith("_")]
        print(f"  [OK] Símbolos integrados: {VOL_SYMBOLS}  ({', '.join(subdirs)})")

    # ── Verificar LM Studio ───────────────────────────────────────────────────
    print(f"\nConectando a LM Studio ({LM_BASE})...")
    model_id, err = check_lmstudio()
    if err:
        print(f"  [ERROR] {err}")
        sys.exit(1)
    print(f"  [OK] Modelo activo: {model_id}")

    # ── Configurar caso ───────────────────────────────────────────────────────
    setup_case()
    select_os()

    active = _plugins_for_os()
    print(f"\n  Plugins activos para {_OS_LABELS[_os_type]}: {len(active)}"
          f"  (de {len(PLUGINS)} totales disponibles)")

    print(AYUDA)
    print("─" * 66)

    history: list[dict] = []

    while True:
        try:
            print()
            question = input("Investigador> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSesión terminada.")
            break

        if not question:
            continue

        cmd = question.lower()

        if cmd in ("salir", "exit", "quit"):
            print("Sesión terminada.")
            break

        elif cmd == "plugins":
            active = _plugins_for_os()
            print(f"\nPlugins activos para {_OS_LABELS[_os_type]} ({len(active)} total):")
            current_prefix = ""
            for name, desc in active.items():
                prefix = name.split(".")[0]
                if prefix != current_prefix:
                    current_prefix = prefix
                    print(f"\n  ── {prefix.upper()} ──")
                print(f"  {name}")
                print(f"      {desc}")

        elif cmd == "cache clear":
            n = clear_cache()
            print(f"  Caché borrado ({n} archivo(s) eliminados).")

        elif cmd == "historial":
            if not history:
                print("  (sin preguntas en esta sesión)")
            else:
                for i, h in enumerate(history, 1):
                    print(f"\n  [{i}] {h['q']}")

        else:
            print()
            answer = run_agent(question, model_id, history)
            print()
            print("═" * 66)
            for line in answer.splitlines():
                if len(line) <= 66:
                    print(line)
                else:
                    for wrapped in textwrap.wrap(line, width=66):
                        print(wrapped)
            print("═" * 66)
            history.append({"q": question, "a": answer})


if __name__ == "__main__":
    main()
