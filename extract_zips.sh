#!/bin/bash

# Define la carpeta principal (por defecto la carpeta actual si no le pasas argumento)
CARPETA_ORIGEN="${1:-.}"

echo "Buscando y extrayendo archivos .zip en: $CARPETA_ORIGEN"
echo "----------------------------------------------------"

# Busca todos los .zip y los procesa
find "$CARPETA_ORIGEN" -type f -name "*.zip" | while read -r zip_file; do
    echo "Extrayendo: $zip_file"
    
    # Obtiene la ruta del directorio donde está el archivo .zip
    dir_destino="$(dirname "$zip_file")"
    
    # Descomprime en la misma carpeta donde se encuentra el .zip
    unzip -q -o "$zip_file" -d "$dir_destino"
    
    echo "✓ Finalizado: $zip_file"
done

echo "----------------------------------------------------"
echo "¡Proceso completado!"