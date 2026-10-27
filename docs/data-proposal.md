# Propunere de dataset: CVE-urile kernelului Linux, etichetate pentru triere

## 1. De ce acest dataset?

Din februarie 2024, echipa kernelului își emite singură CVE-urile și dă un CVE aproape oricărui bug fixat care ar
putea avea impact de securitate. În NVD există acum **21.808 CVE-uri care menționează kernelul Linux**, iar 18.047
dintre ele sunt emise de kernel.org. Până în 2024 erau cel mult câteva sute pe an. În 2024 au fost 4.368, în 2025
5.699, iar în 2026 sunt deja 8.108 până la sfârșitul lui octombrie, adică peste 25 pe zi. Fiecare e, practic, un mesaj
de commit transformat în CVE.

**La ce e bun și cine l-ar folosi.** Cei care trebuie să decidă ce fac cu aceste CVE-uri sunt echipele de securitate
ale distribuțiilor (Debian, Ubuntu, Red Hat), firmele care livrează kerneluri vechi în telefoane, mașini sau routere
și trebuie să aleagă ce fix-uri aduc înapoi (backport), și oricine gestionează vulnerabilitățile pe multe servere
Linux. Toți au aceeași întrebare: *care dintre CVE-urile de azi contează cu adevărat pentru mine?* Datele publice
ajută foarte puțin:

- **22% din CVE-urile emise de kernel.org nu au niciun scor CVSS**, de la nimeni.
- Acolo unde există, scorul aproape nu le deosebește: 89% din CVE-urile kernel.org notate de NVD au primit fie exact
  5.5, fie exact 7.8.
- Sursele nu se pun de acord. Când NVD și kernel.org au notat același CVE (2.647 de cazuri), au dat scoruri diferite
  în 76% din cazuri.
- Tipul de slăbiciune (CWE) lipsește la 45% din CVE-uri și uneori e pur și simplu greșit: CVE-2023-52433 e un
  use-after-free, dar are CWE-ul „Improper Check for Dropped Privileges”.

**Ce aduce în plus față de ce există deja.** NVD și lista CVE sunt datele brute de la care pornim. Repository-ul de
vulnerabilități al kernelului adaugă versiunile afectate și commit-urile de fix, dar nu o evaluare consecventă a
impactului. Distribuțiile triază de mână, fiecare în tracker-ul propriu și pe scala proprie. Seturile de cercetare
precum CVEfixes, Big-Vul sau DiverseVul leagă CVE-urile de codul vulnerabil, ca să antreneze detectoare de bug-uri;
ele nu spun cine poate declanșa bug-ul sau la ce duce, și nu au fost gândite să țină pasul cu valul de după 2024. Din
ce am găsit noi, nimeni nu oferă, pentru fiecare CVE de kernel, aceleași trei răspunsuri: *ce fel de bug e, cine îl
poate declanșa și ce poate obține un atacator.* Asta vrem să adăugăm, iar de aceea construim un set nou în loc să
folosim unul existent.

## 2. Surse

| sursă | ce luăm | licență | dimensiune |
|---|---|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | toate CVE-urile a căror descriere conține „Linux kernel”, cu scorurile CVSS de la fiecare sursă, CWE-urile, verdictul CISA despre exploatare (SSVC) și linkurile de referință | textul CVE: [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse), o licență gratuită și permanentă de reproducere și modificare, cu condiția să păstrăm notița de copyright MITRE și licența. Ce adaugă NVD e lucrare a guvernului SUA; NVD cere doar mențiunea *„This product uses the NVD API but is not endorsed or certified by the NVD.”* | 21.808 CVE-uri, 32 MB în format JSON Lines (instantaneu din 27 oct. 2026) |
| [git.kernel.org, arborele stable](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/) | hash-urile commit-urilor de fix, care apar deja în referințele din NVD (toate cele 18.047 de CVE-uri kernel.org le au) | GPL-2.0 (codul); noi păstrăm doar hash-urile | — |

Descărcarea se face cu un singur script ([`collect.py`](../collect.py)), fără cheie de API, în aproximativ cinci
minute. Căutăm fraza exactă, eliminăm CVE-urile respinse („Rejected”) și păstrăm o singură înregistrare pentru
fiecare ID.

## 3. Date sensibile

Înregistrările sunt rapoarte publice de vulnerabilități: nu conțin pacienți, clienți sau conturi de utilizator. Avem
totuși un lucru de tratat. Descrierile CVE-urilor de kernel sunt mesaje de commit, iar 351 dintre ele conțin adrese
de email ale dezvoltatorilor sau ale celor care au raportat bug-ul. Înlocuim fiecare adresă cu `<email>` chiar în
momentul descărcării, așa că ele nu ajung în fișierele noastre. Numele care apar în text sunt mențiuni publice din
istoria kernelului și le lăsăm neschimbate. Datele complete nu sunt urcate pe GitHub: sunt mari și oricine le poate
reconstrui cu `collect.py`. În repository se află doar un eșantion de 30 de înregistrări, cu adresele deja mascate.

## 4. Schema

Un obiect JSON pe CVE. Primele câmpuri vin direct din NVD sau sunt calculate din el cu reguli simple. Ultimele trei le
vom adăuga cu un LLM și le vom verifica manual.

| câmp | tip | de unde vine | ce înseamnă |
|---|---|---|---|
| `id` | string | original | ID-ul CVE |
| `published` | dată | original | data publicării în NVD |
| `source` | string | original | cine a emis CVE-ul: `kernel.org`, `MITRE`, `Red Hat`, un producător... |
| `description` | string | original, cu email-urile mascate | textul complet în engleză (la kernel.org, mesajul de commit) |
| `title` | string sau null | derivat | prima linie a unei descrieri kernel.org, de ex. `media: uvcvideo: Skip parsing ...` |
| `subsystem` | string sau null | derivat | ce e înainte de primele două puncte din titlu: `net`, `drm/amdgpu`, `wifi`... (azi 2.057 de valori distincte, pe care le vom normaliza) |
| `cwes` | listă de string-uri | original | tipurile de slăbiciune, dacă există |
| `cvss` | obiect | original | câte un scor de bază pentru fiecare sursă, de ex. `{"NVD": 5.5, "CISA-ADP": 4.4}` |
| `exploitation` | string sau null | original (CISA SSVC) | `none`, `poc` sau `active` |
| `fix_commits` | listă de string-uri | derivat din referințe | hash-urile commit-urilor care repară bug-ul |
| `bug_type` | enum | **AI, verificat de noi** | `use-after-free`, `out-of-bounds`, `null-pointer`, `race`, `memory-leak`, `uninitialized-memory`, `integer-overflow`, `missing-check`, `speculation`, `other` |
| `attacker` | enum | **AI, verificat de noi** | cine îl poate declanșa: `remote`, `local-unprivileged`, `local-privileged`, `physical-device`, `unclear` |
| `impact` | enum | **AI, verificat de noi** | cel mai grav rezultat plauzibil: `privilege-escalation`, `memory-corruption`, `information-leak`, `denial-of-service`, `none`, `unclear` |

Trei înregistrări reale. Câmpurile din NVD sunt copiate ca atare (am scurtat doar listele de commit-uri și ultima
descriere). Ultimele trei câmpuri le-am completat noi, de mână, ca să arătăm formatul.

```json
{"id": "CVE-2024-53104", "published": "2024-12-02", "source": "kernel.org",
 "title": "media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format", "subsystem": "media",
 "description": "In the Linux kernel, the following vulnerability has been resolved:\n\nmedia: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format\n\nThis can lead to out of bounds writes since frames of this type were not\ntaken into account when calculating the size of the frames buffer in\nuvc_parse_streaming.",
 "cwes": ["CWE-787"], "cvss": {"NVD": 7.8, "CISA-ADP": 7.8}, "exploitation": "active",
 "fix_commits": ["1ee9d9122801eb688783acd07791f2906b87cb4f", "467d84dc78c9abf6b217ada22b3fdba336262e29"],
 "bug_type": "out-of-bounds", "attacker": "physical-device", "impact": "privilege-escalation"}
```

```json
{"id": "CVE-2023-52433", "published": "2024-02-20", "source": "kernel.org",
 "title": "netfilter: nft_set_rbtree: skip sync GC for new elements in this transaction", "subsystem": "netfilter",
 "description": "In the Linux kernel, the following vulnerability has been resolved:\n\nnetfilter: nft_set_rbtree: skip sync GC for new elements in this transaction\n\nNew elements in this transaction might expired before such transaction\nends. Skip sync GC for such elements otherwise commit path might walk\nover an already released object. Once transaction is finished, async GC\nwill collect such expired element.",
 "cwes": ["CWE-273"], "cvss": {"kernel.org": 7.8, "CISA-ADP": 4.4}, "exploitation": "none",
 "fix_commits": ["03caf75da1059f0460666c826e9f50e13dfd0017", "2ee52ae94baabf7ee09cf2a8d854b990dac5d0e4"],
 "bug_type": "use-after-free", "attacker": "local-unprivileged", "impact": "memory-corruption"}
```

```json
{"id": "CVE-2019-13272", "published": "2019-07-17", "source": "MITRE", "title": null, "subsystem": null,
 "description": "In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). [...]",
 "cwes": [], "cvss": {"NVD": 7.8, "CISA-ADP": 7.8}, "exploitation": "active", "fix_commits": [],
 "bug_type": "missing-check", "attacker": "local-unprivileged", "impact": "privilege-escalation"}
```

Al doilea exemplu rezumă bine problema: kernel.org spune 7.8, CISA spune 4.4, iar CWE-ul e greșit.

## 5. Cum vom arăta că setul e util

Avem două idei. Prima: etichetăm noi, de mână, câteva sute de CVE-uri alese aleator și măsurăm cât de des e LLM-ul
de acord cu noi la fiecare câmp. Așa aflăm cât ne putem baza pe etichete. A doua: CISA a marcat 104 dintre aceste
CVE-uri ca exploatate în practică (30 exploatate activ, 74 cu un proof of concept public). Dacă câmpurile noastre
`attacker` și `impact` valorează ceva, o ordonare după ele ar trebui să aducă aceste 104 CVE-uri în top mult mai bine
decât CVSS, care dă aproape tuturor 5.5 sau 7.8. Ca demonstrație, vom pune setul și în spatele unui mic agent care
caută în el și răspunde la întrebări, cu o buclă de tool calling.

## Eșantion

[`sample.jsonl`](sample.jsonl) conține 30 de înregistrări reale, alese aleator dintre cele 21.808. Au câmpurile
originale și pe cele derivate; câmpurile AI vin în etapa următoare.
