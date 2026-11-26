# P0 statik çekirdek doğrulaması

Taban: `main` / `4ab742fef8a3e3c914ec991f716cb05251587b3f`. Aşağıdaki kontroller yerel değişiklikleri içerir, yayımlanmış sürümü değil. Ortam: macOS arm64, Python 3.12.13, uv 0.12.22. Karşılaştırma: [DSE-001](DSE-001-KARSILASTIRMA.md#birleşik-main-kabulü).

| Görev | Tekrarlanabilir kanıt (`uv run --frozen --offline pytest -q` sonrasındaki dosyalar) |
|---|---|
| DSE-002 | `tests/test_dynamic_mcp.py tests/test_threat_intel.py tests/test_realworld_hardening.py`: karar gerçek `Scanner.scan` hattında; kritik, model notuyla zenginleştirilmiş kritik, doğrulanmış zararlı, operatörce gözden geçirilmiş zararlı ham digest, eksik feed ve bozuk girdide `Popen` çağrısı yok. İzin dalı ayrı testte mock sınıra ulaşır. Kullanıcının makinesindeki mevcut süreçler bu kontrolün kapsamı dışındadır. |
| DSE-003 | `tests/test_scan_budgets.py tests/test_complete_coverage.py`: dosyalar arası ortak limitler, 129. bölge, süre/iptal, bulgu akışını erken kesme, BOM ve ham/metin digest ayrımı. [Limitler ve kesinti noktaları](SCAN_BUDGETS.md). |
| DSE-004/006 | `tests/test_skill_packages.py`: doğrudan/kurulu keşif, frontmatter, kayıp/döngü/symlink, belirsiz veya pasif referans ve somut skill → yardımcı bağlantısı. [Desteklenen paket kapsamı](skill-packages.md). |
| DSE-005/007 | `tests/test_dse_command_and_prompt.py tests/test_complete_coverage.py`: PowerShell'de aynı girdiyi yürütme noktasına bağlama, argv/stdin negatifleri, EN/TR etkin cümleler ve iki MCP metadata alanı. [Kanıt sınırları](KOMUT-VE-METAVERI-KANITI.md). |
| DSE-008 | `tests/test_coverage_inventory.py tests/test_evidence_contract.py tests/test_sarif.py tests/test_cli_interface.py tests/test_cli_ux.py`: karar tablosu, dört kanıt türü, tarama kapsamı, bulgu/tanı/yol maskelemesi, public kimlikler ve CLI `0/1/2/3`. [Rapor sözleşmesi](EVIDENCE_CONTRACT.md). |

[144 önerinin karar tablosunda](reference-rule-ledger.csv) 8 `existing` ve 8 `revise` satırının her biri [Ek B'deki](../Dragons-Technical-Assessment-2026-11-26.md#ek-b-ayrıntılı-tespit-kuralı-envanteri) ürün kimliğine ve onu bekleyen [benchmark vakasına](../benchmarks/corpus/manifest.json) bağlı. 13 `new` satırı [§15'teki](../Dragons-Security-Engine-Development-Guide-v2.md#15-detection-rule-backlog) tasarımlardır. Yalnız aileye ayrılmış 115 numaraya P0'da ayrı ürün kuralı atanmaması kararlaştırıldı. Her `deferred` satırında gerekçe, yeniden değerlendirme görevi ve gerekli ayırt edici kanıt yazılı; bu numaralar uygulama veya test kapsamı değildir.

`tests/test_coverage_inventory.py` 144 kimliğin tekilliğini, görev bağlantılarını ve Ek B'deki 48 public kimliğin güncel 49 üreticide korunduğunu denetler. Eşlenmiş 16 kuralın vaka dosyalarını statik tarayıp kaydedilen kural ve kanıt türünün gerçekten üretildiğini de sınar. `tests/test_cli_interface.py` ve `tests/test_cli_ux.py` ile birlikte **42 test geçti**. Geliştirme manifesti yeniden tarandı: 48 vaka, **50 TP / 0 FP / 0 FN**; `scripts.benchmark_gate` geçti.

## Doğruluk karşılaştırması

P0 kapanışında `uv run --frozen --offline pytest -q -rs --tb=line`: **2704 geçti, 7 atlandı** (117,07 s). Altı YARA-X testi ayrı yorumlayıcı gerektiriyor; bir Windows ACL testi macOS'ta uygulanmıyor. `uv lock --check --offline`, Ruff format/lint, `mypy src scripts` (78 kaynak), `git diff --check` ve çevrimdışı sdist → wheel derlemesi geçti. Önceki P0 ölçümünde `scripts.semantic_benchmark` çevrimdışı tamamlandı; `scripts/performance_baseline.py --smoke` içindeki beş senaryonun tamamı `ok`. Bunlar canlı model veya tam ölçek performans testi değildir. `tests/test_vulnerability.py` ve `tests/test_dynamic_mcp.py` varsayılan taramanın ağ ve süreç sınırlarını; `tests/test_evidence_contract.py` kısmi analizin temiz sayılmadığını sınar.

Kontrol sonrası kaynak parmak izi: `06621310abb6bd649541452c9f96daf7f89a044a3d1ed5b2d144c7518d604f0d`. Kapsam: `git ls-files -co --exclude-standard` ile seçilen `src`, `tests`, `scripts`, `pyproject.toml`, `uv.lock`; sıralı her mevcut dosya için göreli yol baytları, NUL ve ham SHA-256'nın birleştirilmiş SHA-256'sı. Belge değişikliği veya eski benchmark çıktılarını içermez.

`scripts.benchmark` ile aynı beş manifest, `scripts.benchmark_gate` ile geliştirme çıktısı ve `scripts.phase6_evaluation` ile kilitli `benchmarks/phase6-v2/manifest.json` kullanıldı. Tümü yerel; etiketler ve var olan vaka eşikleri değişmedi. Geliştirme kapısının katalog sayımı yeni `DRAGON-EXEC-004` ile 48'den 49'a çıktı; vaka sayısı değişmedi.

| Ölçüm | Vaka | TP / FP / FN |
|---|---:|---:|
| Geliştirme (`corpus`) | 48 | 50 / 0 / 0 |
| `realworld` | 5 | 4 / 0 / 0 |
| `holdout` | 1 | 0 / 0 / 0 |
| `phase2-v2` | 10 | 8 / 0 / 0 |
| `interpreter` | 13 | 4 / 0 / 0 |
| Phase 6 v2 | 36 | 24 / 0 / 0 |

Bunlar DSE-001 ile karşılaştırılabilir yerel sonuçlardır, kör doğruluk tahmini veya runtime saldırı önleme ölçümü değildir. Harici provider, canlı hedef, OS sandbox ve diğer işletim sistemleri doğrulanmadı.
