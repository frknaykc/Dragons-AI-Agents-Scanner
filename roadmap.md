# Dragons Security Engine: geliştirme yol haritası

[Rehber v2](Dragons-Security-Engine-Development-Guide-v2.md) §17 görev kapsamını ve bağımlılıkları, §4 hedef mimariyi, §16 ve §18 doğrulama ölçütlerini tanımlar. Bu dosya faz durumunun kaydıdır. [IDEA.md](IDEA.md) ürün vizyonunu, [README.md](README.md) ise bugün desteklenen davranışı anlatır. Hedef, mevcut statik motoru genişletmek ve yalnızca doğrulanabilen sınırlarda isteğe bağlı runtime koruması eklemektir.

## Faz takibi

- [ ] **P0 · Güvenilir başlangıç ve statik çekirdek**
- [ ] **P1 · Genişletilmiş statik analiz ve izole MCP incelemesi**
- [ ] **P2 · İsteğe bağlı runtime denetimi ve bağımsız doğrulama**
- [ ] **P3 · Onaylanan platformlar ve ileri entegrasyonlar**

İlk adım **DSE-001**: yerel değişikliklerle `origin/main` arasından doğrulanacak kaynak ve corpus sürümlerini seçmek. Aşağıdaki ön inceleme bir fazı kapatmaz. Eski `benchmarks/phase*` sonuçları bu fazların tamamlandığını göstermez.

**Nasıl güncellenir?** Aşağıdaki görevleri bağımlılık sırasıyla ele al. “Önkoşul” sütunundaki sayılar `DSE-` görev numaralarıdır. Bir görev doğrulandığında aynı değişiklikte görev kutusunu işaretle ve satıra kanıt kaydının yolunu ekle. Kayıtta snapshot, çalıştırılan komutlar, sonuçlar ve kapsam sınırları bulunmalı. Tüm zorunlu görevler ve fazın kapanış ölçütü doğrulanınca yukarıdaki faz kutusunu `[x]` yap. Engelli veya ertelenmiş işi işaretleme; nedenini ve devam koşulunu ilgili satıra yaz. Kapsam değişikliği kullanıcı kararı gerektirir.

## Repo ön incelemesi · 2026-11-26

**Hangi ağaç ölçüldü?** macOS 27.0 arm64 üzerinde, yerel `main` (`db23dd5`) ve commit edilmemiş değişiklikler. Yerelde kayıtlı `origin/main` (`26a5700`) 11 commit ileride; fetch, pull veya birleştirme yapılmadı. İki commit arasında değişen 50 yolun çalışma ağacındaki içerikleri karşılaştırıldı: 11'i `origin/main` ile aynı, 27'si hâlâ `HEAD` ile aynı, 12'si ikisinden de farklı. Son grupta `behavior.py`, `mcp_security.py`, `attack_graph.py` ve `tests/test_benchmark.py` var. Dolayısıyla ne yerel `HEAD` ne de `origin/main` tek başına aşağıdaki sonuçları tanımlar.

| Yerel kontrol | Sonuç | Geliştirme kararı |
|---|---|---|
| Kilit ve kalite | `uv lock --check --offline` geçti. Python 3.12.13, uv 0.12.22: pytest **2286 geçti, 7 atlandı**; Ruff format/lint ve mypy (`src`, `scripts`) geçti. | Yerel kalite CI'ında Python 3.12.12 ve uv 0.11.7 sabit. Onaylanan ağaçta CI sürümleriyle tekrar ölç; atlananları platform desteği olarak gösterme. |
| Geliştirme corpus'u | 48 vaka, **49 TP / 1 FP / 1 FN**. Tarama komutu 0, ayrı `benchmark_gate` **1** döndürdü. `mcp-poisoning` için beklenen `DAAS-002`, çıkan `DRAGON-MCP-004`. | `scripts/benchmark_gate.py` 50/0/0 bekliyor. Gate'i gevşetmeden önce onaylanan fixture ve komut yorumunu karşılaştır. |
| Dondurulmuş Phase 6 v2 | 36 vaka, **17 TP / 0 FP / 7 FN**, strict runner çıkışı **1**. Eksikler iki dosyalar arası zincirde ve üç yürütme örneğinde. | `e596852` corpus, manifest ve ground-truth kilidinde düzeltmeler içeriyor. Yereldeki 7 eksik sonucu doğrudan 7 dedektör hatası sayma. DSE-005/006'da yalnız yeniden üretilen farkları ele al. |
| Diğer çevrimdışı kontroller | Real-world pilot: 5 vaka, 4 TP, 0 FP/FN. Negatif holdout: 1 vaka, 0 FP. Phase 2 v2: 10 vaka ve interpreter: 13 vaka, ikisinde de 0 FP/FN. Semantik runner tamamlandı; sağlayıcı ölçülmedi. Performans smoke: 5/5 senaryo `ok`. | Bunlar bilinen örneklerdir. Tek makinedeki smoke sonucu performans hedefi, bu holdout da DSE-021 için kör veri değildir. |

**Kodun plana etkisi:**

- **DSE-002/015:** `src/dragonscan/scanner.py:548–578` önce hata/diagnostic kontrolüyle dinamik incelemeye karar veriyor, sonra TI eşleşmesini hesaplıyor. `dynamic_mcp.py:101` izolasyonsuz mod için zaten ayrı onay istiyor. Eksik iş onay bayrağı değil; başlatma öncesi kanıta dayalı veto ve daha sonra doğrulanmış izolasyon backend'i.
- **DSE-003–009/016:** `loading.py` dosya başına 1 MiB sınırı, `discovery.py` dolaşım limitleri, `markdown_parser.py` Cursor frontmatter desteği, `correlation.py` mevcut `DRAGON-PATH-002` yollarını içeriyor. `mcp_security.py:93–172` birden fazla yerde `instructions or description` seçiyor. `parsing.py` yapılandırma ve Markdown ayrıştırıyor; bu, referans verilen Python kodunun AST analizi değil. Komut, OpenClaw alan eşlemesi ve keşifte yerel işe başlamadan `1738a06`, `f88053f`, `26a5700` ve testleriyle karşılaştır.
- **DSE-010–014:** HTTPS edinimi (`target_acquisition.py`), paket/sürüm bazlı zafiyet sorgusu (`vulnerability.py`), MCP normalizasyonu ve sır referansları (`mcp_normalization.py`) mevcut. `threat_intel.py:351–395` SHA-256, sürüm düşürme kontrolü ve atomik değiştirme uyguluyor. Bunları yeniden yazmak yerine domain geçmişi, zararlı paket kimliği, yayıncı imzası/iptal ve onaylı MCP şema geçmişi için ayrı kanıt iste.
- **DSE-017–022:** `policy.py` tamamlanmış taramanın **CI** kararını veriyor; bir agent eylemini durdurduğunu göstermiyor. `signature_yara.py` bir adapter sözleşmesi, varsayılan YARA motoru değil. Mevcut benchmark, semantik analiz veya wheel kayıtlarını runtime engelleme, kör doğruluk ya da yeni snapshot için sürüm kanıtı sayma.

**Tekrar yolu:** Çevrimdışı `uv run --frozen --offline` ile `pytest -q`, `ruff format --check .`, `ruff check .`, `mypy src`, `mypy scripts`; `python -m scripts.benchmark benchmarks/<corpus>/manifest.json --format json` (`corpus`, `realworld`, `holdout`, `phase2-v2`, `interpreter`). Geliştirme JSON'unu repo dışına yazıp `python -m scripts.benchmark_gate <json>` çalıştır. Diğer girişler: `python -m scripts.phase6_evaluation benchmarks/phase6-v2/manifest.json`, `python -m scripts.semantic_benchmark benchmarks/semantic/corpus/manifest.json --format json`, `python scripts/performance_baseline.py --smoke`. Bu incelemede diğer işletim sistemleri, canlı sağlayıcı, release build ve tam performans profili doğrulanmadı.

## P0 · Güvenilir başlangıç ve statik çekirdek

İlk dalgada runtime adapter geliştirilmez. Önce mevcut davranışı ölç, sonra tarayıcının kendi başlatma ve kaynak sınırlarını güvenceye al.

| Görev | Önkoşul | Teslim ve kabul kanıtı |
|---|---|---|
| [ ] DSE-001 · Kaynak seçimi ve tekrarlanabilir başlangıç ölçümü | Yok | Önce yerel çalışma, upstream düzeltmeleri ve corpus/kilit sürümlerini ayır; kullanıcının onayladığı ayrı snapshot üzerinde commit, çalışma ağacı ve lock kimliklerini kaydet. Kalite ve strict doğruluk kapılarını ayrı çalıştır, zor negatifleri ve performans smoke sonuçlarını yeni kayda yaz. İki kırmızı kapıyı yeniden ölç; kalan farklar için vaka, beklenen/gözlenen sonuç ve sonraki görev kaydı oluştur. Başarısız, atlanan ve çalıştırılmayan kontrolleri ayır; ürün kodunu veya tarihsel beklentileri değiştirme. |
| [ ] DSE-002 · Dinamik MCP başlatma kararı | 001 | Statik bulgular ve gerekli TI eşleşmeleri başlatmadan önce değerlendirilsin. Kritik, doğrulanmış zararlı veya eksik analizde mock `Popen` çağrısı sıfır olmalı. İzolasyonsuz başlatma varsayılan olmasın; CI çıkış politikası değişmesin. |
| [ ] DSE-003 · Toplam kaynak bütçeleri | 001 | Dosya, bayt, bölge, görünüm ve bulgu limitlerini tarama genelinde uygula. Çok sayıda küçük dosya, 129+ bölge ve iptal örneklerinde sınırlı çıktı ve `incomplete`; BOM örneğinde ham bayt ve metin özetleri ayrılmalı. |
| [ ] DSE-004 · Skill paketi keşfi | 003 | Seçilen paket kökünde frontmatter, yardımcı dosyalar ve iç içe referansları envantere al. Döngü, kayıp hedef, sınır dışı symlink ve bozuk frontmatter için kapsamı bildir. Doğrudan ve kurulu paket taraması aynı kapsamı vermeli. |
| [ ] DSE-005 · Ortak komut analizi ve PowerShell | 001, 004 | Dedektörler `argv`, `stdin` ve alıntıları aynı biçimde yorumlasın. İnert PowerShell örneğinde uzak içerikten yürütme noktasına bağlantı `High`; yalnız indirme veya doküman alıntısı aynı bulguyu üretmemeli. Alt süreç başlatılmamalı. |
| [ ] DSE-006 · Dosyalar arası kanıt zinciri | 004, 005 | Skill → script bağlantısını ve kanıt varsa `PATH-002` ilişkisini göster. Belirsiz hedef, ilişkisiz dosya veya yalnızca decode edilmiş görünüm yürütme zinciri oluşturmamalı. |
| [ ] DSE-007 · Prompt ve MCP metadata doğruluğu | 001 | EN/TR etkin talimatı alıntı ve olumsuzlamadan ayır. `description` ve `instructions` birlikte bulununca ikisini de incele. İlişkisiz okuma ve yükleme veri sızıntısı sayılmamalı; model görüşü danışma amaçlı kalmalı. |
| [ ] DSE-008 · Kural kataloğu ve rapor sözleşmesi | 002–007 | §15.A'daki her referans kimliğini `existing/revise/new/deferred/not-applicable` olarak görev ve testle ya da gerekçeyle eşle. §4.B ortak kimlik sözleşmesini tanımla. Terminal/JSON/SARIF'te kanıt türü, kapsam ve maskeleme tutarlı olmalı; mevcut public ID'ler ve `0/1/2/3` çıkış kodları korunmalı. |

**Kapanış:** DSE-001 ölçümüne göre açıklanmamış regresyon kalmamalı. Varsayılan taramanın ağa çıkmadığı ve hedefi çalıştırmadığı, kısmi analizin temiz sonuç vermediği ve reddedilen MCP'nin başlatılmadığı testlerle gösterilmeli.

## P1 · Genişletilmiş statik analiz ve izole MCP incelemesi

| Görev | Önkoşul | Teslim ve kabul kanıtı |
|---|---|---|
| [ ] DSE-009 · Kaynak kod ayrıştırıcıları | 004, 005, 006 | Önce Python AST, ardından sınırları belirtilmiş shell/PowerShell/JS analizi. Referans verilen script içindeki kaynak-hedef ilişkisini import etmeden bul; dinamik sözdizimini `partial` olarak bildir. |
| [ ] DSE-010 · Web girdisi ve domain kanıtı | 003, 005, 007 | Yerel HTML/README ve kayıtlı arama yanıtını kaynak konumuyla incele. RDAP açık onay gerektirsin; timeout, NXDOMAIN ve geçmiş sahiplik kanıtını ayır. İçerikteki URL izlenmemeli, açıkça istenen edinimde her yönlendirme yeniden denetlenmeli. |
| [ ] DSE-011 · Paket kimliği ve registry | 005, 008 | Zararlı paket kaydını güvenlik açığından ayır. Aynı adlı farklı kaynak/sürüm, geri çekilmiş kayıt ve erişilemeyen özel registry yanlış eşleşmemeli. Paket kurmadan doğrula. |
| [ ] DSE-012 · Doğrulanmış istihbarat güncellemeleri | 003, 008 | İmza, süre, iptal ve sürüm geri alma kontrollerini atomik depolamayla birleştir. Geçersiz güncelleme veya aynı sürümde farklı içerik eski geçerli kaydı bozmamalı. Doğrulanmamış feed tek başına engelleme yetkisi vermemeli. |
| [ ] DSE-013 · Sırlar, etkin izinler ve kalıcılık | 007, 009 | Hassas yol, dosyada yazılı sır, etkin config ve kalıcılık kanıtlarını ayır. Açık anahtar, sahte değer, pasif profil ve izinli değişiklik zor negatiflerdir. Sentetik sır hiçbir çıktıda açık görünmemeli. |
| [ ] DSE-014 · MCP şema değişiklikleri | 002, 008 | Operatör onaylı yerel snapshot ile nitelikli sunucu ve araç kimliğini karşılaştır. Anahtar sırası aynı özeti vermeli; anlamlı değişiklik görünmeli. Eksik snapshot otomatik yenilenmemeli; test sunucu başlatmamalı. |
| [ ] DSE-015 · İzole dinamik MCP backend'i | 002, 003, 014 | Yetkilendirilmiş ortamda zararsız test süreciyle dosya/ağ sınırını, kaynak kotalarını ve alt süreç temizliğini doğrula. Desteklenmeyen platformda başlatma reddedilmeli. Linux ilk adaydır, kesinleşmiş platform değildir. |
| [ ] DSE-016 · Agent adapter uyumluluğu | 004, 013 | Seçilen agent ve sürümler için config önceliğini sürümlü fixture'larla doğrula. Doğrudan/proje/kurulu tarama sonuçlarını karşılaştır; çözülmeyen öncelik `unknown` kalmalı. |

**Kapanış:** Yeni yüzeylerin her biri için pozitif, zor negatif ve eksik kapsam örnekleri bulunmalı. Varsayılan tarama çevrimdışı kalmalı; izole MCP desteği yalnızca DSE-015 testinin geçtiği platform için belirtilmeli. P2'ye başlamadan kullanıcı ilk runtime agent'ını ve hedef işletim sistemini seçmeli.

## P2 · İsteğe bağlı runtime denetimi ve bağımsız doğrulama

| Görev | Önkoşul | Teslim ve kabul kanıtı |
|---|---|---|
| [ ] DSE-017 · Preflight, watch ve bütünlük | 008, 014 | Korumalı manifest üzerinden değişen dosyayı yeniden tara ve eski onayı geçersiz kıl. Yeniden adlandırma, olay kaybı ve kısmi tarama görünür olmalı. Watch gözlemdir; engelleme sonucu üretmemeli. |
| [ ] DSE-018 · Tek agent için işlem öncesi denetim | 015, 017 | Seçilen agent'ın belgelenmiş hook'unda `ALLOW/WARN/HOLD/BLOCK` kararını eylem kimliğine bağla. Ret durumunda sentetik yan etki oluşmamalı; timeout veya adapter hatası zorlanan kapsamda işleme izin vermemeli. |
| [ ] DSE-019 · MCP stdio proxy | 014, 015, 018 | Reddedilen istek sunucuya iletilmemeli; desteklenen sınırda riskli yanıt modele ulaşmadan tutulmalı. Normal çağrılar ve protokol korunmalı. Yanıtı tutmak sunucudaki önceki işlemi geri almış sayılmaz. |
| [ ] DSE-020 · Web olayları ve nedensel korelasyon | 010, 018, 019 | Statik ve runtime hatları §4.B'deki aynı kesin kimlik ve istihbarat kurallarını kullansın. Kaynak ile eylemi kimlikle bağla; zaman yakınlığı yeterli değildir. Görünmeyen tarayıcı işlemleri `unknown` kalmalı. §4.C bütünleşik senaryolarını doğrula. |
| [ ] DSE-021 · Kör değerlendirme ve sürüm doğrulaması | 008–020, geçerli kapsam | Ayarlamada kullanılmamış, bağımsız etiketli holdout üzerinde kategori/dil bazında sonuçlar; platform desteği, kapsam, gecikme ve tepe RSS yayımla. Snapshot, tekrar komutları ve başarısız/ölçülemeyen sonuçları kaydet. |

**Kapanış:** §4.C'nin altı senaryosu kayıtlı olmalı: temiz skill ve izinli çağrı; sentetik README → yardımcı script zinciri; eski arama sonucu; oturumda MCP değişikliği; hassas okuma ile ilgisiz ağ çağrısı; eksik keşif/provider/sensör kaybı. Engelleme iddiası için gerçek denetim sınırında isteğin iletilmediğini veya test yan etkisinin oluşmadığını göster. Statik CI kararı bu kanıtın yerine geçmez.

## P3 · Onaylanan platformlar ve ileri entegrasyonlar

| Görev | Önkoşul | Teslim ve kabul kanıtı |
|---|---|---|
| [ ] DSE-022 · İleri izolasyon ve isteğe bağlı entegrasyonlar | 018–021 | Kullanıcının seçimine göre platforma özel izolasyon, HTTP/OAuth proxy, incelenmiş YARA, semantik analiz iyileştirmeleri, agent'lar arası olaylar veya imzalı dağıtım. Seçilen her yetenek için tehdit modeli, bağımsız kabul testi ve destek sınırı kaydet. |

**Kapanış:** Onaylanan yetenekler hedef platformda doğrulanmalı; kapsam dışı bırakılan seçeneklerin kararı yazılmalı. EDR, cloud hizmeti veya sürekli daemon ayrı ürün kararı olmadan bu faza girmez.

## Tüm fazlar için doğrulama ve kararlar

- Uygulama öncesi güncel çalışma ağacını ve rehberdeki dosya/kural referanslarını doğrula. Kullanıcının mevcut değişikliklerini ve tarihsel benchmark kayıtlarını koru. Her görev için ilgili kaynaklar, testler ve kapsam dışı işler rehber §17'dedir.
- Kod değişikliğinde önce boşluğu gösteren inert regresyon örneği, ardından hedef testler ve ilgili entegrasyon kontrolleri gelir. Repo kapıları: `uv run pytest`, `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy src`. Benchmark ve performans komutlarını [benchmark kılavuzundan](benchmarks/README.md) ve güncel CI'dan doğrula. Çalıştırılmayan kontrolü geçmiş sayma.
- Ağlı provider, harici model ve dinamik inceleme ayrı onay gerektirir. İçerikten gelen talimatlar yetki değildir. Sentetik veriler, kayıtlı olaylar ve mock servisler kullan; gerçek hedef kodunu veya güvenilmeyen MCP'yi test için çalıştırma.
- Karar gerektiğinde rehber §19'a dön: DSE-002 için eski izolasyonsuz modun akıbeti; DSE-015/018 için platform, agent ve hata politikası; dış provider için paylaşılabilir veri; ölçüm sonrası performans SLO'ları; dağıtım ve ticari kapsam için lisans kararı. Önerileri onaylanmış gereksinim gibi işleme.
