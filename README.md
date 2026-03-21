# 🔑 qmrClau — Gestor de Contrasenyes Portable

**qmrClau** és un gestor de contrasenyes local, xifrat i portable per a Windows 10/11 i Linux, inspirat en KeePass. Totes les dades es guarden en un únic fitxer `.vkdb` xifrat amb AES-256 que només tu pots obrir amb la teva contrasenya mestra.

L'aplicació no requereix instal·lació ni connexió a Internet per funcionar: és un executable únic que pots portar en un USB. Opcionalment, pots emmagatzemar la base de dades en un servidor FTP per accedir-hi des de qualsevol lloc.

> **Zero dependències externes** · **AES-256-CBC** · **PBKDF2-SHA256** · **Python pur**

---

## Característiques

### Seguretat
- **Xifrat AES-256-CBC** amb clau derivada per **PBKDF2-SHA256** (200.000 iteracions)
- **HMAC-SHA256** per verificar la integritat del fitxer
- **Zero dependències externes** — AES, PBKDF2 i HMAC implementats en Python pur
- **Generador de contrasenyes** segur (usa `secrets`, CSPRNG del sistema operatiu)
- **Indicador de fortalesa** visual de contrasenya en temps real
- **Auto-neteja del portapapers** als 15 segons després de copiar una contrasenya
- **Verificació de contrasenya mestra** abans d'exportar o importar dades

### Organització
- **Grups i subgrups jeràrquics** — estructura d'arbre il·limitada (com KeePass)
- **Arbre visual** al panell lateral amb `Treeview` desplegable
- **Moure grups** a qualsevol altre lloc de l'arbre
- **Moure entrades** entre grups amb el botó 📦
- **Breadcrumb** que mostra el camí complet del grup actiu (p.ex. "Arrel / Feina / Servidors")

### Cerca Global
- **Camp de cerca a la barra d'eines** — cerca a tota la base de dades (tots els grups i subgrups)
- Cerca dins dels camps títol, usuari, URL i notes
- Cada resultat mostra el **camí del grup** on es troba
- Botó **📂 Anar al grup** per navegar directament a l'entrada trobada
- Botó **📋** per copiar la contrasenya des dels resultats

### Exportació i Importació
- **Exportar a CSV** — exporta totes les entrades amb la ruta del grup, compatible amb Excel
- **Importar des de CSV** — importa des de fitxers de KeePass, Bitwarden o del mateix qmrClau
- Detecció automàtica de columnes en català i anglès (`Títol`/`Title`, `Usuari`/`Username`, etc.)
- Crea automàticament els grups que no existeixin durant la importació
- Avís de seguretat abans d'exportar (les contrasenyes queden en text pla al CSV)

### Accés remot via FTP
- **Obrir bases de dades des d'un servidor FTP** per accedir des de llocs diferents
- Suport per a FTP estàndard i **FTPS** (FTP amb xifrat TLS)
- Si el fitxer no existeix al servidor, **el crea automàticament**
- En cada desada, el fitxer xifrat es **puja automàticament al servidor FTP**
- Recorda la darrera configuració de connexió (servidor, port, usuari, ruta)
- En tancar, elimina el fitxer temporal local per no deixar dades al disc

### Interfície
- **Tema fosc** modern
- **Finestres de diàleg centrades** respecte a la finestra principal
- **Tooltips** a tots els botons amb descripció de l'acció
- **Doble-clic** sobre una entrada per obrir-la i editar-la directament
- **Resum de notes** visible a la targeta de cada entrada
- **Camp de notes ampliable** — la finestra d'edició és redimensionable
- **Icona de clau** a la barra de títol
- **Diàleg de grups** amb el mateix estil visual que la resta de l'aplicació
- **Executable portable** — un sol fitxer, sense instal·lació
- **Multiplataforma** — Windows 10/11 i Linux
- **Reanomenar grups** amb doble-clic, botó ✏️, o clic dret
- **Pregunta en tancar** si hi ha canvis pendents sense desar

### Configuració
- **Fitxer de configuració** (`qmrclau.json`) — es crea automàticament al costat de l'executable
- **Obrir darrera base de dades** — a la pantalla d'inici apareix un botó per obrir directament la darrera BD utilitzada
- Recorda la darrera configuració FTP utilitzada

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
4. **Obrir des de FTP**: Introdueix les dades del servidor FTP i la ruta del fitxer
5. Gestiona les teves entrades organitzades per grups i subgrups
6. Usa el botó 📋 per copiar contrasenyes al portapapers

### Accions ràpides

| Acció | Com fer-ho |
|---|---|
| Editar una entrada | Doble-clic sobre la targeta |
| Copiar contrasenya | Botó 📋 a la targeta |
| Moure entrada | Botó 📦 a la targeta |
| Eliminar entrada | Botó 🗑️ a la targeta |
| Reanomenar grup | Doble-clic, botó ✏️ o clic dret |
| Afegir subgrup | Botó `+ Subgrup` al panell lateral o clic dret |
| Moure grup | Clic dret → Moure a... |
| Generar contrasenya | Botó 🎲 al formulari d'entrada |
| Generador independent | Botó ⚡ Generador a la barra d'eines |
| Cerca global | Camp 🔍 a la barra d'eines (prémer Enter) |
| Tancar cerca | Tecla Escape o botó ✕ |
| Exportar a CSV | Botó 📤 Exportar a la barra d'eines |
| Importar des de CSV | Botó 📥 Importar a la barra d'eines |

---

## Seguretat

| Component         | Detall                                    |
|-------------------|-------------------------------------------|
| Xifratge          | AES-256-CBC                               |
| Derivació de clau | PBKDF2-HMAC-SHA256, 200.000 iteracions    |
| Integritat        | HMAC-SHA256                               |
| RNG               | `secrets` (CSPRNG del sistema operatiu)   |
| Portapapers       | Auto-neteja als 15 segons                 |
| Exportació        | Requereix confirmació de contrasenya mestra |

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

## Format CSV d'exportació/importació

```
Grup,Títol,Usuari,Contrasenya,URL,Notes
Arrel/General,Exemple,usuari@mail.com,contrasenya123,https://exemple.com,Nota opcional
Arrel/Banca,Banc XYZ,12345678,secret,,
```

**Compatibilitat d'importació:** el camp `Grup` accepta rutes separades per `/` o `\`. Les columnes es detecten automàticament per nom en català (`Títol`, `Usuari`, `Contrasenya`) o anglès (`Title`, `Username`, `Password`, `URL`, `Notes`).

---

## Accés remot via FTP

Per compartir la base de dades entre dispositius:

1. Crea un servidor FTP (p.ex. FileZilla Server) accessible des d'Internet o xarxa local
2. A qmrClau, clica **🌐 Obrir des de FTP** i introdueix:
   - **Servidor**: adreça IP o domini del servidor FTP
   - **Port**: 21 (FTP) o 990 (FTPS)
   - **Usuari / Contrasenya FTP**: credencials del servidor
   - **Ruta del fitxer**: p.ex. `/qmrclau/mydb.vkdb`
   - **Connexió segura (FTPS)**: recomanat si el servidor ho suporta
3. Si el fitxer no existeix, es crea automàticament
4. Cada desada puja el fitxer xifrat al servidor

> ⚠️ El fitxer `.vkdb` sempre viatja **xifrat**. Ni el servidor FTP ni l'administrador poden llegir les contrasenyes.

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
- L'accés FTP és seqüencial: si dues persones desen alhora, l'última desada sobreescriu l'anterior. Es recomana un ús no simultani.
- Fes còpies de seguretat del teu fitxer `.vkdb`!

---

## Llicència

Ús lliure. Modifica'l com vulguis.
