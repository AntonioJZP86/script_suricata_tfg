# script_suricata_tfg
Script en Bash para la gestión de laboratorios en Suricata como IDS/IPS. Proyecto Trabajo fin de Grado

# Script de Gestión para Suricata IDS/IPS (TFG)

Este script, `swich_suricata_mode.sh` ha sido desarrollado como herramienta auxiliar.

## Motivación

Durante el desarrollo de los laboratorios prácticos del TFG se hizo evidente la necesidad de cambiar frecuentemente entre los diferentes modos en Suricata, el modo IDS y el IPS. Gestionar el servicio y consultar los gos para analizar los resultados que se obtenian. 

El script tiene como objetivo automatizar y centralizar estas operaciones optimizando el flujo de trabajo, esto permite centrarse en el análisis de los ataques y respuesta de Suricata.



## Características Principales

El script proporciona una interfaz de menú interactiva basada en texto permitiendo las siguientes tareas:

* **Cambio rápido de modo de operación:**
    * **Modo IDS (af-packet):** Limpia las reglas de `iptables` para una monitorización pasiva.
    * **Modo IPS (NFQUEUE):** Añade la regla `iptables` necesaria para la intercepción activa del tráfico.
* **Gestión del Servicio de Suricata:** Permite iniciar, consultar el estado y detener el servicio `suricata` (compatible con `systemd`).
* **Visualización de Logs Optimizada:**
    * Muestra las últimas alertas de archivo `eve.json` formateadas usando `jq`.
    * Filtra y muestra alertas con acción `DROP`.
    * Permite ver alertas en tiempo real a traves del el archivo `fast.log` .
* **Gestión de Archivos de Log:**
    * Exporta las alertas (todas o solo las `DROP`) a un archivo JSON para su tradado posterior.
    * Vacía los archivos de log (`eve.json` y `fast.log`) solicitando confirmación.
* **Interfaz:** El menú principal indica en todo momento el modo que actualmente se encuentra (IDS o IPS).

## Requisitos

Para poder utilizar el script es necesario contar con lo siguiente (probado en Ubuntu Server 24.04):

* Suricata instalado y configurado como un servicio de `systemd`.
* Permisos de superusuario (el script debe ejecutarse con `sudo`).
* La herramienta `jq` instalada para el formateo de los logs JSON. Se puede instalar con:
    ```bash
    sudo apt update && sudo apt install jq
    ```

## Uso

1.  Clona este repositorio en tu máquina:
    ```bash
    git clone [https://github.com/tu-usuario/script_suricata_tfg.git](https://github.com/tu-usuario/script_suricata_tfg.git)
    ```
    *(Reemplaza `tu-usuario` y `TFG-Suricata-Script` por tu nombre de usuario y el de tu repositorio)*

2.  Navega al directorio del proyecto:
    ```bash
    cd script_suricata_tfg
    ```

3.  Dar permisos de ejecución al script:
    ```bash
    chmod +x script_suricata_tfg.sh
    ```

4.  Ejecuta el script con `sudo`:
    ```bash
    sudo ./script_suricata_tfg.sh
    ```

## Licencia

Este proyecto se distribuye bajo la Licencia MIT.