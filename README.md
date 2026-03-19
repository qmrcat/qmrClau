# 🔐 qmrClau — Gestor de Contrasenyes Portable

Gestor de contrasenyes local, xifrat i **portable** per a Windows 10/11 i Linux.
Inspirat en KeePass, sense cap dependència externa.

---

## Característiques

### Seguretat
- **Xifrat AES-256-CBC** amb clau derivada per **PBKDF2-SHA256** (200.000 iteracions)
- **HMAC-SHA256** per verificar la integritat del fitxer
- **Zero dependències externes** — AES, PBKDF2 i HMAC implementats en Python pur
- **Generador de contrasenyes** segur (usa `secrets`, CSPRNG del sistema operatiu)
- **Indicador de fortalesa** visual de contrasenya
- **Auto-neteja del portapapers** als 15 segons després de copiar una contrasenya

### Organització
- **Grups i subgrups jeràrquics** — estructura d'arbre il·limitada (com KeePass)
- **Arbre visual** al panell lateral amb `Treeview` desplegable
- **Moure grups** a qualsevol altre lloc de l'arbre
- **Moure entrades** entre grups amb el botó 📦
- **Breadcrumb** que mostra el camí complet del grup actiu (p.ex. "Arrel / Feina / Servidors")

### Cerca Global
- **Camp de cerca a la barra de menú** — cerca a tota la base de dades (tots els grups i subgrups)
- Cerca dins dels camps títol, usuari, URL i notes
- Cada resultat mostra el **camí del grup** on es troba
- Botó **📂 Anar al grup** per navegar directament a l'entrada trobada
- Botó **📋** per copiar la contrasenya des dels resultats

### Interfície
- **Tema fosc** modern
- **Executable portable** — un sol fitxer, sense instal·lació
- **Multiplataforma** — Windows 10/11 i Linux
- **Reanomenar grups** amb doble-clic, botó ✏️, o clic dret
- **Pregunta en tancar** si hi ha canvis pendents sense desar

### Configuració
- **Fitxer de configuració** (`qmrclau.json`) — es crea automàticament al costat de l'executable
- **Obrir darrera base de dades** — a la pantalla d'inici apareix un botó per obrir directament la darrera BD utilitzada
- Extensible per a futures configuracions

---

## Com generar l'executable

### Windows (.exe)

**Requisits:** Python 3.8+ instal·lat ([python.org](https://python.org))

1. Posa els fitxers del projecte en una carpeta
2. Fes doble clic a `generar_exe.bat`
3. Espera 1-2 minuts
4. L'executable apareix a `dist\qmrClau.exe`

Alternativa manual:

```
pip install pyinstaller
pyinstaller --onefile --noconsole --name qmrClau --clean qmrclau.py
```

### Linux (binari portable)

**Requisits:** Python 3.8+ i tkinter

```bash
# Instal·lar tkinter si cal (Ubuntu/Debian)
sudo apt install python3-tk

# Generar executable
chmod +x generar_exe.sh
./generar_exe.sh
```

L'executable apareix a `dist/qmrClau`.

L'executable generat a Ubuntu funciona a Ubuntu i derivats (Mint, Pop!_OS...). Per a Fedora o Arch, cal compilar-lo a la mateixa família de distribució.

---

## Ús

1. Executa `qmrClau.exe` (Windows) o `./qmrClau` (Linux) o `python qmrclau.py` (desenvolupament)
2. **Crear Base de Dades**: Tria on desar el fitxer `.vkdb` i crea una contrasenya mestra
3. **Obrir Base de Dades**: Selecciona un fitxer `.vkdb` existent
4. Gestiona les teves entrades organitzades per grups i subgrups
5. Usa el botó 📋 per copiar contrasenyes al portapapers

### Accions ràpides

- **Clic dret** sobre un grup → Afegir subgrup, Reanomenar, Moure, Eliminar
- **Doble-clic** sobre un grup → Reanomenar
- **✏️** al panell dret → Reanomenar el grup actiu
- **🎲** al formulari d'entrada → Genera contrasenya aleatòria
- **📦** a una entrada → Moure-la a un altre grup
- **⚡ Generador** → Generador de contrasenyes independent
- **🔍 Cerca** a la barra de menú → Cerca global (prémer Enter)
- **Escape** al camp de cerca → Tancar cerca

---

## Seguretat

| Component         | Detall                                    |
|-------------------|-------------------------------------------|
| Xifratge          | AES-256-CBC                               |
| Derivació de clau | PBKDF2-HMAC-SHA256, 200.000 iteracions    |
| Integritat        | HMAC-SHA256                               |
| RNG               | `secrets` (CSPRNG del sistema operatiu)   |
| Portapapers       | Auto-neteja als 15 segons                 |

### Format del fitxer `.vkdb`

```
[4 bytes]  Magic: "VKDB"
[2 bytes]  Versió (big-endian) — actual: v3
[32 bytes] Salt (aleatori)
[16 bytes] IV (aleatori)
[32 bytes] HMAC-SHA256 (salt + iv + ciphertext)
[N bytes]  Ciphertext (AES-256-CBC, PKCS7)
```

### Estructura de dades (JSON xifrat)

```json
{
  "root": {
    "id": "uuid",
    "name": "Arrel",
    "entries": [],
    "children": [
      {
        "id": "uuid",
        "name": "Feina",
        "entries": [{"title": "...", "username": "...", "password": "...", "url": "...", "notes": "..."}],
        "children": [
          {"id": "uuid", "name": "Servidors", "entries": [...], "children": [...]}
        ]
      }
    ]
  },
  "meta": {"created": "...", "modified": "...", "version": 3}
}
```

### Compatibilitat

- **Migració automàtica** — els fitxers `.vkdb` creats amb la versió anterior (v2, grups plans) es converteixen automàticament a l'estructura d'arbre (v3) en obrir-los
- Els fitxers `.vkdb` són compatibles entre Windows i Linux

---

## Estructura del projecte

```
qmrclau/
├── qmrclau.py        ← Codi principal (tot en un fitxer)
├── qmrclau.json      ← Configuració (es genera automàticament)
├── generar_exe.bat    ← Script per generar .exe (Windows)
├── generar_exe.sh     ← Script per generar binari (Linux)
└── README.md          ← Documentació
```

---

## Limitacions i notes

- La implementació d'AES és en Python pur: funcional i correcta, però més lenta que una
  implementació en C. Per a bases de dades amb centenars d'entrades funciona bé; si notes
  lentitud, pots instal·lar `pycryptodome` i adaptar el codi.
- No hi ha sincronització al núvol — és un gestor **local i offline**.
- Fes còpies de seguretat del teu fitxer `.vkdb`!

---

## Llicència

Ús lliure. Modifica'l com vulguis.