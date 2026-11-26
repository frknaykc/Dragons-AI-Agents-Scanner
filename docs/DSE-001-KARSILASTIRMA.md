# DSE-001 · Checkpoint ve main karşılaştırması

26 Kasım 2026. Amaç: iki daldaki kod ve test verisini birbirinden ayırarak geliştirme tabanını seçmek. Bu kayıt birleşik bir sürümün kabulü değildir. `git ls-remote` ile doğrulanan iki commit ayrı, başlangıçta temiz klonlarda incelendi. Mevcut çalışma dizini, izlenmeyen raporlar ve özel semantik sonuçlar ölçüme dahil edilmedi.

| Kimlik | Checkpoint | `origin/main` |
|---|---|---|
| Commit | `53afdc9f02e4e665f41a5dd3163273227754a4f6` | `26a570028811351b531f34864571bf9232aa4560` |
| Git tree | `fe3848e896ee6496e97b5069daea1127a9331f91` | `aea5fba58285bd426f700d8a3a0b9f8f663ad409` |
| Phase 6 v2 manifest SHA-256 | `a65b25c0b7b5d448cb152c37200310648806a91a7840798da262ee2991fece68` | `35ee7d795111ba9cf00e6a5c2daef1e8022aca3a0fd1970de94a6306487a722b` |

Ortak ata `db23dd52fab34a15346df05f69c6b289ef4b680c`; sonrasında checkpoint'te 1, main'de 11 commit var. İki sürümde `uv.lock` SHA-256 aynı: `f67697f8b3783566adffa20546396f37feb604dffc60203367f412573188abe3`. Ortam macOS 27.0 arm64, Python 3.12.12, uv 0.12.22, pytest 9.1.1, Ruff 0.16.8 ve mypy 1.20.2. Kalite workflow'undaki uv 0.11.7 kullanılmadı.

## İki tarayıcı × iki veri seti sürümü

Her satırda kod, sol sütundaki klondan; fixture, manifest ve ground-truth kilidi ikinci sütundaki klondan geldi. Ölçüm sırasında bunlar değiştirilmedi. Sayılar **doğru pozitif / yanlış pozitif / yanlış negatif** sırasındadır.

| Tarayıcı | Test verisi | Geliştirme seti (48 vaka) | Phase 6 v2 (36 vaka) | İki strict kontrol |
|---|---|---:|---:|---|
| Checkpoint | Checkpoint | 49 / 1 / 1 | 17 / 0 / 7 | İkisi de başarısız |
| Main | Checkpoint | 49 / 1 / 1 | 17 / 0 / 7 | İkisi de başarısız |
| Checkpoint | Main | 50 / 0 / 0 | 24 / 0 / 0 | İkisi de geçti |
| Main | Main | 50 / 0 / 0 | 24 / 0 / 0 | İkisi de geçti |

Bu iki kontrolde sonucu değiştiren, tarayıcı dalı değil **test verisi sürümü** oldu. `e596852`, örnekleri, manifesti ve kilidi birlikte düzeltiyor. Bunu dedektör iyileştirmesi veya kör veri üzerinde doğruluk artışı olarak sayma. Dört geliştirme koşusunda da 31 zor-negatif kontrol değerlendirildi.

Eski veriyle yeniden üretilen farklar:

| Vaka | Beklenen | Gözlenen |
|---|---|---|
| `mcp-poisoning` | `DAAS-002` | Onun yerine `DRAGON-MCP-004` |
| `chain-local-load`, `chain-structured-load` | Her birinde `DRAGON-EXEC-001` ve `DRAGON-PATH-002` | Dördü de yok |
| `exec-network-python`, `exec-shell-fetch`, `obf-literal-shell` | Sırasıyla `DRAGON-EXEC-002`, `DRAGON-EXEC-001`, `DRAGON-EXEC-003` | Üçü de yok |

Düzeltilmiş veride bu farklar kalmadı. Bunları DSE-005/006 için ürün hatası olarak açmak yerine, birleşik adayda her iki strict kontrolü değiştirmeden yeniden çalıştır.

## Diğer yerel kontroller

Tam pytest paketi checkpoint'te **2286 geçti, 7 atlandı**; main'de **2551 geçti, 1 atlandı**. İki klonda da Windows ACL testi macOS'ta atlandı; checkpoint'teki ek altı test ayrı YARA-X yorumlayıcısı gerektiriyor. İki klonun da Git çalışma ağacı testlerden sonra temizdi.

Her iki klonda Ruff biçim/lint, mypy (`src scripts`), geliştirme dışı real-world pilot (5 vaka, 4 doğru pozitif), negatif holdout (1 vaka, 0 yanlış pozitif), çevrimdışı semantik değerlendirme, performans smoke (5/5) ve sdist → wheel derlemesi geçti. Canlı sağlayıcı, diğer işletim sistemleri, yayımlanmış paket veya tam performans profili sınanmadı. Semantik runner'ın başarılı çıkışı sağlayıcı doğruluğu ölçümü değildir.

## Hangi değişiklikler korunmalı?

**Karar:** Yerel checkpoint temel alınacak; `26a5700` içindeki GitHub’a özgü düzeltmeler aynı `main` dalında birleştirilecek. Yeni dal açılmayacak. `git merge-tree --write-tree --name-only 53afdc9 26a5700` çalışma ağacını değiştirmeden 10 dosyada çatışma bildirdi. Başarılı otomatik metin birleştirmesi davranış doğrulaması sayılmaz.

| Kapsam | Entegrasyon kararı önerisi |
|---|---|
| `attack_graph.py`, `detectors.py`, `mcp_security.py`, `rules.py` | Main'in ortak `shell_command_string` seçimini ve agent config kapsamını koru. Bunları yardımcı fonksiyonun tanımlandığı `behavior.py` ve main'in komut sınırı testleriyle birlikte al. |
| `tests/test_benchmark.py` | Beklentiyi tek başına seçme. Main'in onaylı verisi, manifest/kilidi, ilgili testleri ve mevcut strict kapısı birlikte kalmalı. |
| `docs/DETECTION_ACCURACY_REVIEW.md`, `docs/POST_RELEASE_DETECTION_REVIEW.md`, `docs/REFERENCE.md` | Güncel tespit ve kapsam sözleşmesini main'den al; checkpoint'in hâlâ geçerli sınırlarını koru. Eski sayıları yeni adaya aitmiş gibi aktarma. |
| `docs/INSTALLATION.md`, `docs/WHEEL_RELEASE_CANDIDATE.md` | Main'deki wheel adayının kimliğini ve doğrulanmış kapsamını koru. Checkpoint'teki platform/lisans çalışmalarını aynı wheel için kanıt olarak göstermeden birleştir. |
| Checkpoint'e özgü işler | Kök rehber ve roadmap, Phase 2 v2 örnekleri, izole Phase 4 deneyi, Windows paketleme, runtime lisans kontrolleri, bunların testleri ve release belgeleri kaybolmamalı. Main'in keşif/OpenClaw düzeltmeleri ve testleri de korunmalı. |

## Tekrar ve kapanış

1. Tablodaki iki commit'i ayrı temiz klonlarda checkout et. Her birinde `uv sync --locked --offline --python 3.12.12` çalıştır. Aşağıdaki Python araçlarını aynı klonda `uv run --locked --offline` ile çağır.
2. Her kod klonunda, `DATA` değişkeni sırayla **her iki klonun mutlak yolunu** gösterirken `python -m scripts.benchmark "$DATA/benchmarks/corpus/manifest.json" --format json > "$OUT/corpus.json"` ve `python -m scripts.benchmark_gate "$OUT/corpus.json"` çalıştır. Her koşu için repo dışında ayrı `OUT` dizini kullan. Phase 6 için `python -m scripts.phase6_evaluation "$DATA/benchmarks/phase6-v2/manifest.json"` çalıştır.
3. Her klonun kendi verisiyle `pytest -q -rs`, `ruff format --check .`, `ruff check .`, `mypy src scripts`; `scripts.benchmark` ile `realworld` ve `holdout` manifestleri; `python -m scripts.semantic_benchmark benchmarks/semantic/corpus/manifest.json --format json` ve `python scripts/performance_baseline.py --smoke` çalıştır. Dağıtım derlemesi için `uv build --offline --out-dir "$OUT/dist"` kullan.
4. DSE-001'i kapatmak için birleşik `main` adayının commit/tree/lock kimliğini kaydet ve kapıları o ağaçta çalıştır. İki ayrı dalda alınan sonuçları birleşik adayın sonucu olarak kullanma.

## Birleşik main kabulü

26 Kasım 2026: Yerel checkpoint ile `26a5700` geçmişleri `main` üzerinde birleştirildi. Yukarıdaki komutlar bu kez tek bir temiz klonda, aynı commit'in kodu ve verisiyle çalıştırıldı. Commit `a150340d52a7bfa88a030bf525291b15e86923d2`, tree `5292a81e4421ca8ef98a5eb9f240f0c65c115de4`; çalışma ağacı kontrollerden sonra temizdi. `uv.lock` özeti yukarıdakiyle aynı; Phase 6 v2 `ground_truth.lock.json` SHA-256: `dbfaa81c29d92728603d0fb338e1bfcc002b2cfae12ae141c666aba735626643`.

| Kontrol | Birleşik sürümde sonuç |
|---|---|
| Yazılım kalitesi | Python 3.12.12, macOS arm64: pytest **2580 geçti, 7 atlandı** (6 izole YARA-X, 1 Windows ACL). Ruff format ve lint, `mypy src scripts`, `uv lock --check --offline` geçti. |
| İki strict doğruluk kapısı | Geliştirme: 48 vakada **50 TP / 0 FP / 0 FN**; 31 zor negatifte hata yok. Phase 6 v2: 36 vakada **24 / 0 / 0**. Önceki kırmızı kapılardan bu veride açık fark kalmadı. |
| Diğer veri setleri | Real-world **4 / 0 / 0**, negatif holdout **0 / 0 / 0**, Phase 2 v2 **8 / 0 / 0**, interpreter **4 / 0 / 0**. Bunlar bağımsız kör doğruluk ölçümü değildir. |
| Performans ve derleme | `files:10`, `oversize:1`, `ioc:10`, `graph:20`, `high_branch:50`: **5/5 `ok`**. Çevrimdışı semantik runner ve sdist → wheel derlemesi tamamlandı. |

Yerel doğrulamada uv 0.12.22 kullanıldı. Bu kayıt GitHub CI, diğer işletim sistemleri, canlı sağlayıcı, tam performans profili veya yayımlanmış paket için kabul değildir. DSE-001 kapandı; P0'ın diğer görevleri açık.
