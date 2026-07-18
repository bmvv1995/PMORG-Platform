# PMORG v3 — handoff Sol desktop → sesiunea VPS

| Câmp | Valoare |
|---|---|
| Handoff | `PMORG-V3-VPS-2026-07-18` |
| Autor | Sol — sesiunea Codex Desktop de pe calculatorul ownerului |
| Destinatar | următoarea sesiune Sol/Codex de pe VPS |
| Statut | checkpoint WIP transferabil; **nu** baseline aprobat și **nu** Gate A PASS |
| Repo de implementare | `bmvv1995/PMORG-Platform` |
| Branch de transfer | `sol/checkpoint-v3-g3a-vps-20260718` |
| Canon de produs | `bmvv1995/PMORG` la `6cf92cb1c7148b916929fb04f7f24f62bcab184d` (`RB-1/C1`) |
| Upstream Onyx | tag `v4.3.9`, commit `1da679cefc96165c6b9b64c3bc769584b88f88c2` |

> Commitul care conține acest document este snapshotul autoritativ al
> transferului tehnic. El conservă inclusiv starea WIP și datoriile cunoscute;
> nu transformă acea stare în produs calificat. Canonul normativ rămâne repo-ul
> `PMORG` la commitul indicat mai sus.

## 1. Protocol de trezire pe VPS

Nu începe prin a modifica codul. Începe prin a reconstrui adevărul comun:

```bash
git clone https://github.com/bmvv1995/PMORG-Platform.git
cd PMORG-Platform
git fetch origin
git switch --detach origin/sol/checkpoint-v3-g3a-vps-20260718
git status --short
git rev-parse HEAD
```

Creează branch-ul de continuare numai după ce SHA-ul din mesajul de predare a
fost verificat:

```bash
git switch -c sol/v3-vps-continuation
```

Clonează separat canonul de produs și fixează exact baseline-ul:

```bash
git clone https://github.com/bmvv1995/PMORG.git ../PMORG
git -C ../PMORG fetch origin
git -C ../PMORG switch --detach 6cf92cb1c7148b916929fb04f7f24f62bcab184d
```

La fiecare sesiune și înaintea fiecărei noi felii de lucru:

1. `git fetch` în ambele repo-uri;
2. citește corespondența nouă și PR-urile deschise;
3. nu face auto-merge și nu înlocui starea locală cu remote-ul;
4. ancorează afirmațiile în commit, fișier/linie sau output de test.

## 2. Cerința de produs, în formularea ownerului

PMORG este un **operator organizațional persistent peste ERP**, capabil să:

1. primească sau să identifice o inițiativă;
2. discute cu persoanele relevante;
3. clarifice obiectivul și constrângerile;
4. genereze planul și taskurile;
5. identifice responsabili și termene;
6. obțină confirmări;
7. urmărească execuția zile sau luni;
8. observe lipsa progresului și blocajele;
9. inițieze singur conversații;
10. adapteze planul;
11. escaladeze când este necesar;
12. verifice rezultatul și să închidă bucla.

Produsul trebuie să fie business-focused și agnostic față de organizație.
Evaluarea folosește trei modele de organizații, nu un singur client mascat ca
produs generic.

### Constrângeri explicite ale ownerului

- **zero teste în producție**;
- MVP-ul folosește exclusiv date, identități, credențiale și canale sintetice
  sau dedicate;
- ERP-ul nu este opțional: este ancora formală și ontologia domeniului;
- Odoo este alegerea validată pentru ancora ERP;
- LLM self-hosted nu este tratat drept garanție de confidențialitate și nu este
  o problemă pe care proiectul trebuie să o rezolve;
- ownerul decide direcțiile de produs; implementarea tehnică este delegată;
- nu cere ownerului detalii de programare. Ridică doar alegeri strategice care
  modifică produsul, riscul sau ordinea de validare.

## 3. Arhitectura votată

```text
Oameni / canale
       ↕
Communication Gateway
       ↕
Orchestrator extern (Hermes este candidat, nu cerință nominală)
       ↕ execute_cognitive_step / Turn API
PMORG-Platform — fork controlat Onyx
  ├─ strat cognitiv și knowledge Onyx
  ├─ PMORG application/domain core
  └─ PMORG Semantic Core / organizational ledger
       ↕
Odoo — control plane, muncă formală și closed-world anchor
```

Formularea „PMORG devine core al Onyx” descrie produsul și ownership-ul. Nu
interzice ca Semantic Core să fie un bounded context și un serviciu
independent deployabil, cu schema, rolul DB, backup-ul și migrațiile sale.

### Ownership-ul adevărului

- Odoo deține starea formală curentă: organizații, companii, oameni,
  inițiative, taskuri, termene, aprobări, rezultate și procesele modulelor
  active.
- Semantic Core deține evidence, claims, assessments, contradicții,
  supersessions, commitments semantice, receipts și istoria organizațională.
- Onyx knowledge/vector/KG sunt proiecții reconstructibile, nu ledgerul
  organizațional.
- Orchestratorul deține progresul execuției și checkpointurile sale, dar nu
  inventează adevăr și nu devine al doilea work registry.
- Hermes Kanban nu este sursa canonică a muncii; `project.task` extins în Odoo
  este registrul canonic.

### Closed world și vocabular

- Capability registry-ul se derivă determinist din modulele Odoo active,
  companie, ACL, policy și anchor packs aprobate.
- Modulele active introduc entitățile de prim nivel relevante. Exemplu: HR
  activ permite vocabular HR; HR absent înseamnă că acel vocabular nu este
  presupus și nici simulat tăcut.
- Starea live Odoo prevalează pentru faptele formale curente.
- Informația din afara closed world poate deveni evidence/propunere, nu adevăr
  organizațional automat.
- Human-in-the-loop este permis pentru vocabular și reconcilierea ancorelor.
  Interpretarea semantică a claimului nu intră într-o coadă de adnotare umană:
  sistemul consemnează cu receipt dacă politica permite, altfel tace.

## 4. Ierarhia repo-urilor și a adevărului

### `PMORG` — canon normativ

Baseline: `RB-1/C1` la
`6cf92cb1c7148b916929fb04f7f24f62bcab184d`.

Citește în această ordine:

1. `README.md`;
2. `docs/correspondence/000-claude-catre-sol.md`;
3. `docs/correspondence/001-claude-catre-sol-review-v3.md`;
4. `docs/correspondence/001a-decizie-owner.md`;
5. `docs/pmorg-v3/03-DECISIONS.md` — în special ADR-315/316;
6. `docs/pmorg-v3/08-REQUIREMENTS-BASELINE.md`;
7. `docs/pmorg-v3/09-CONTRACTS.md`;
8. `docs/pmorg-v3/12-ACCEPTANCE-TRACEABILITY.md`;
9. `docs/pmorg-v3/14-V2-CONTRACT-SUPERSESSION.md`.

`PMORG` stabilește ce trebuie construit. Nu porta mecanic implementarea v2/SB3
și nu schimba contractele înghețate prin adaptări locale în fork.

### `PMORG-Platform` — implementarea Onyx/PMORG

- `origin/main` la momentul predării: `446dc1fdbc1574bad9f61ea8ea9de9bc9172136b`;
- fundația curată: branch `sol/v3-foundation`, commit
  `ff3b2e371686e4f3fb3885af289f9eb7f6dae969`, draft PR #17;
- acest checkpoint provine din scratch-ul
  `sol/g3a-ce-artifact-bootstrap`, pornit la
  `689e9d676e3e4a64bb1c4bedf8b09875519bf3c3`;
- scratch-ul era cu două commituri în urma `sol/v3-foundation` la transfer.

Nu face rebase direct al checkpointului. După stabilizarea codului, reconstruiește
felii reviewabile pe baza `sol/v3-foundation` și păstrează checkpointul ca
provenance.

## 5. Protocolul cu Fable / Claude

În conversația ownerului, agentul este numit **Fable**. În repo, scrisorile
sunt semnate **Claude**. Tratează-le drept aceeași contraparte dacă ownerul nu
spune explicit altceva. Contul GitHub poate apărea tehnic drept `bmvv1995`;
atribuirea Sol/Fable vine din semnătură și conținut.

Protocolul din scrisoarea 000 este acceptat fără obiecții:

- Sol lucrează pe `sol/*`, Fable pe `claude/*`, `master` este canon;
- reconcilierea se face prin PR și review încrucișat;
- canonul normativ cere și ownerul;
- probele preced argumentele;
- scrisorile numerotate sunt pentru design în amonte sau dezacorduri de
  principiu, nu pentru status zilnic;
- repo-ul este inbox-ul comun;
- nicio modificare nu intră în master numai fiindcă suitele sunt verzi.

### Schimburile închise

1. Scrisoarea 001 a ridicat cinci corecții: supersession v2→v3, comenzile
   longitudinale, eliminarea `under_review` semantic, casa detectorului de gol
   și Turn Admission înaintea persistenței/Hermes.
2. Ownerul a decis în 001a că review-ul este strict vocabular/ancoră și că
   detectorul de gol intră explicit în v3.
3. Sol a răspuns prin PMORG PR #3, nu prin scrisoarea 002. Corecțiile și cele
   trei note ulterioare au fost tratate; PR-ul a devenit `RB-1/C1` la
   `6cf92cb...`.
4. PMORG-Platform Issue #16 este închis ca rezolvat.

Nu există `002-sol-catre-claude.md`; absența lui este intenționată.

### Schimbul deschis la momentul predării

- PMORG PR #4, branch `claude/idempotency-conflict`, commit
  `a3c3715cf6e1f8b359f8d733aa4debefd3c26dac`, este deschis și mergeable.
- Fable adaugă `E_IDEMPOTENCY_CONFLICT` în inboxul v2 și cere review Sol asupra
  alegerii `json.dumps(sort_keys)` versus RFC 8785.
- Review-ul trebuie făcut separat, ancorat în diff și contracte. Nu îl combina
  cu checkpointul Gate A.
- PMORG-Platform PR #17 este draft, deschis și fără comentarii la momentul
  predării; viitorul review Fable va veni acolo sau într-un PR stacked.

Linkuri:

- PMORG-Platform Issue #16:
  <https://github.com/bmvv1995/PMORG-Platform/issues/16>
- PMORG PR #3:
  <https://github.com/bmvv1995/PMORG/pull/3>
- PMORG PR #4:
  <https://github.com/bmvv1995/PMORG/pull/4>
- PMORG-Platform PR #17:
  <https://github.com/bmvv1995/PMORG-Platform/pull/17>

## 6. Ce conține checkpointul de implementare

Munca este o fundație Gate A pentru forkul Onyx, nu încă funcționalitatea
PMORG de business.

Implementat:

- Dockerfile CE dedicat pentru backend și web;
- excluderea arborilor Onyx EE din contextele de build;
- export backend legat de grupul de dependențe backend, nu grupul EE;
- entrypoint backend fail-closed pentru flaguri EE, telemetrie și auto-config;
- seams frontend/backend înguste pentru a permite artefact CE fără rescrierea
  generală a Onyx;
- overlay de build CE;
- overlay runtime redus la PostgreSQL + API + web, rețea internă și ingress
  web numai pe loopback;
- PostgreSQL `15.18-alpine3.23`, pinuit pe manifestul `linux/amd64`
  `sha256:870f35a8c9eff7ba79a599794120d326df4cecbc6a1bfc0050d58805e37abfaf`;
- verificator source/import/Docker/layer/artifact CE;
- verificatorul a fost împărțit într-o facade și module tematice sub
  `pmorg/scripts/ce_boundary/`;
- generator atomic de evidence pentru arhive Docker și filesystem export;
- patch ledger extins cu `PL-003`–`PL-006`;
- negative tests pentru importuri/paths EE, binding de artefact, identitate,
  dependency export, runtime flags și topologia Compose.

Nu este implementat încă:

- Odoo în sandboxul V3;
- cele trei profiluri organizaționale;
- contract spine `backend/pmorg`;
- Semantic Core și baza sa separată;
- Turn API / integrarea Onyx cognitivă;
- orchestrarea simulată longitudinal;
- canale reale;
- SBOM/licensing/vulnerability/provenance complet;
- backup/restore și cele trei porniri curate.

## 7. Starea verificărilor la transfer

Verificat pe calculator înaintea checkpointului:

- `python3 -m unittest discover -s pmorg/tests -p 'test_*.py'`:
  **32/32 PASS**;
- `python3 -m unittest discover -s pmorg/tests/ce_boundary -p 'test_*.py'`:
  **28/28 PASS**;
- source CE gate: **PASS**, 3.028 fișiere inspectate, zero încălcări;
- `verify_ce_boundary.py --help`: funcțional;
- `generate_ce_evidence.py --help`: funcțional;
- `git diff --check`: curat;
- web: cele trei suite Jest țintite și typecheck au trecut înaintea transferului;
- build checks Dockerfile au trecut pentru imagini locale anterioare.

Limitări ale acestor rezultate:

- Python-ul local implicit nu avea `pytest`; comenzile de predare folosesc
  `unittest` explicit;
- `uv` local este `0.10.2`, în timp ce calificarea cere exact `0.11.25`;
- imaginile locale au fost construite înaintea ultimelor hardenings și au label
  `revision=uncommitted`; nu sunt evidence;
- nu există build calificat din HEAD curat;
- Gate A rămâne **PENDING**.

## 8. Datorii tehnice cunoscute în snapshot

Acestea sunt intenționat conservate, nu ascunse:

1. Refactorizarea `ce_evidence` a fost întreruptă la mutarea sesiunii.
   Generatorul monolitic de 586 linii rămâne funcțional, dar modulele noi din
   `pmorg/scripts/ce_evidence/` sunt parțiale; `__init__.py` referă încă un
   `publish.py` inexistent. Prima acțiune pe VPS este finalizarea refactorului
   sau eliminarea explicită a duplicatelor, apoi teste.
2. Patch ledger-ul nu acoperă încă modulele noi `ce_boundary`, `ce_evidence`
   și testele mutate. `verify_fork.py` trebuie să revină la ownership unic și
   complet înaintea unui PR.
3. `unittest discover -s pmorg/tests` nu descoperă recursiv cele 28 de teste
   `ce_boundary`. Repară discovery-ul ori păstrează două comenzi canonice.
4. Compose cere variabile de imagine, dar interpolarea Compose nu poate valida
   singură că valoarea este chiar un digest calificat.
5. `LICENSE` este montată pentru smoke, nu inclusă încă în imaginile finale;
   nu există încă THIRD-PARTY-NOTICES verificabil.
6. Instalările `apt`, `apk`, Chromium/Playwright și `postgresql-client` rămân
   surse mutable de build.
7. Branch-ul checkpoint nu este bazat pe ultimul `sol/v3-foundation`; nu îl
   prezenta ca serie finală de PR-uri.

## 9. Descoperirea OCI care nu trebuie pierdută

Docker poate expune trei identități diferite pentru același artefact:

1. digestul indexului OCI / valoarea locală `.Id`;
2. digestul manifestului exact `linux/amd64`;
3. digestul configului OCI din `docker save`.

Pe Docker Desktop cu containerd, `repository@digestul-indexului` poate fi
executabil local, în timp ce `repository@digestul-manifestului-platformei` nu
este neapărat rezolvabil în image store. Config digestul leagă layerele și
configurația, dar nu este automat referința de runtime ori dovada
A-SUPPLY-001.

Extensia corectă trebuie să păstreze și să verifice explicit lanțul:

```text
runtime/index digest
  → platform manifest digest (linux/amd64)
  → config digest
  → layer diff IDs și filesystem export
```

Nu redenumi toate acestea generic `image_id`. Generatorul CE și viitorul
image-lock supply-chain trebuie să le separe semantic.

## 10. Sandbox de evaluare versus gate de distribuție

Ultima discuție a identificat că lucrul a alunecat de la „sandbox sigur pentru
validarea produsului” spre „artefact comercial complet auditabil”. Nu este o
criză de arhitectură; este o diferență de nivel de asigurare.

Recomandarea Sol, încă nepromovată într-o decizie normativă separată, este să
menținem două piste:

### Pista EVAL — prioritară

- izolare reală și zero producție;
- date și identități sintetice;
- Odoo + PostgreSQL + Onyx/PMORG în același sandbox controlat;
- imagini și surse pin-uite;
- verificare zero Onyx EE în artefactele PMORG;
- egress SUT blocat;
- backup/restore;
- trei porniri curate;
- prima buclă PMORG longitudinală cu orchestrator simulat.

### Pista DISTRIBUTION — obligatorie înaintea distribuției, neblocantă pentru
validarea inițială

- SBOM Syft/SPDX/CycloneDX;
- Grype offline cu DB pinuită și proaspătă;
- policy de licențe și notices;
- zero Critical/High netriate, waiver-uri exacte și expirabile;
- provenance semnată și digesturi de registry;
- builduri reproductibile ori toate sursele mutable explicit blocate.

Nu slăbi `A-LIC-001`: absența codului Onyx EE rămâne o condiție separată.
Nu declara `A-SUPPLY-001` doar pe baza config digestului sau a unui SBOM
nelegat de manifest.

Ownerul a cerut handoff-ul înainte de a confirma formal această împărțire ca
schimbare a planului. Pe VPS, trateaz-o ca recomandare de execuție și
semnalează ownerului numai dacă ordinea schimbă o decizie strategică.

## 11. Ordinea recomandată pe VPS

1. Verifică SHA-ul checkpointului și rulează scanarea de secrete înaintea
   oricărei publicări suplimentare.
2. Finalizează sau elimină refactorul parțial `ce_evidence`.
3. Repară patch-ledger ownership și test discovery; rulează cele 60 de teste.
4. Nu extinde acum supply-chain-ul comercial. Închide numai invariantul OCI
   necesar pentru a ști exact ce artefact rulează.
5. Reconstruiește schimbările în felii curate peste `sol/v3-foundation`; nu
   transforma checkpointul într-un PR monolitic.
6. Construiește sandboxul EVAL complet, incluzând Odoo și baze separate, cu
   volume sintetice și egress blocat.
7. Portează cele trei organization manifests și capability registries înainte
   de a presupune entități Odoo.
8. Implementează contract spine și Semantic Core evidence kernel conform
   `plans/pmorg-v3-foundation.md`, fără a inventa un API paralel.
9. Simulează orchestratorul pentru prima buclă longitudinală. Hermes și
   canalele reale vin după ce această buclă este reproductibilă.
10. Abia apoi reia pista de distribuție și Gate A complet.

## 12. Interdicții pentru sesiunea care preia

- Nu testa pe date, canale, utilizatori sau credențiale de producție.
- Nu face merge în `main`/`master` fără protocolul Sol–Fable și owner unde
  canonul este atins.
- Nu declara Gate A PASS pe baza testelor source-only.
- Nu folosi imaginile locale `revision=uncommitted` drept evidence.
- Nu porta întregul SB3 sau vechiul experiment CE prin copiere oarbă.
- Nu muta work registry-ul din Odoo în Hermes/Onyx.
- Nu transforma Onyx personal memory în memorie organizațională.
- Nu permite modelului să scrie generic în Odoo sau în ledger.
- Nu interpreta lipsa unui modul Odoo drept permisiunea de a-i inventa
  vocabularul.
- Nu folosi un răspuns LLM drept adevăr, aprobare sau receipt.
- Nu include secrete în handoff, loguri, evidence sau commituri.

## 13. Comenzi minime de verificare după checkout

```bash
git status --short
git rev-parse HEAD
git diff --check HEAD^

python3 -m unittest discover -s pmorg/tests -p 'test_*.py'
python3 -m unittest discover -s pmorg/tests/ce_boundary -p 'test_*.py'

python3 pmorg/scripts/verify_ce_boundary.py source \
  --repository-root . \
  --dockerfile backend/Dockerfile.pmorg-ce \
  --dockerfile web/Dockerfile.pmorg-ce
```

`verify_fork.py` este așteptat să semnaleze ownership incomplet până la
rezolvarea datoriei din §8; nu ocoli eșecul și nu modifica testul ca să ascunzi
căile neacoperite.

## 14. Definition of Done pentru transfer

Transferul este reușit când sesiunea VPS poate demonstra:

- checkout la SHA-ul exact al checkpointului;
- acces read-only la canonul PMORG `6cf92cb...`;
- citirea documentului și a corespondenței 000/001/001a;
- recunoașterea PR #4 ca inbox deschis Fable;
- reproducerea celor 32 + 28 teste locale;
- un branch nou de continuare, fără modificarea checkpointului;
- un prim status în repo sau către owner care separă faptele verificate de
  planurile încă neexecutate.
