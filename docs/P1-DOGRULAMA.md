# P1 yerel doğrulama kaydı · 2026-11-27

**Durum: 8/8 görev doğrulandı.** [Yol haritası](../roadmap.md) görev bazında testlere bağlanır. Aşağıdaki genel kontroller macOS 27 arm64 üzerinde `8788ad1` tabanlı çalışma ağacında yapıldı. DSE-015 canlı kabulü aynı wheel ile ayrı bir Ubuntu ARM64 ortamında yapıldı. Bunlar GitHub CI sonucu değildir. Wheel SHA-256: `4a5b7fa77b0ae9d1bd6dce9213c73495553995a369548e64bedd1d452d1a9118`.

| Kontrol | Yerel sonuç |
|---|---|
| `uv run --offline --frozen pytest -q -rs --tb=line` | 2937 geçti, 8 atlandı. Atlananlar: izole MCP canlı kabulü (1), ayrı YARA-X yorumlayıcısı gerektiren testler (6), Windows ACL testi (1). |
| `uv run --offline --frozen ruff format --check .` ve `uv run --offline --frozen ruff check .` | Biçim (443 dosya) ve lint geçti. |
| `uv run --offline --frozen mypy src` | 74 kaynak dosyasında tip hatası bulunmadı. |
| `uv build --offline` | Kaynak dağıtımı ve wheel derlendi. |
| `uv run --offline --frozen python -m scripts.benchmark benchmarks/corpus/manifest.json --format json` | Yerel corpus üzerinde rapor üretildi; bu raporu okuyan `scripts.benchmark_gate` sonucu `Benchmark v2 baseline: PASS`. Bu eşik sandbox doğrulaması değildir. |
| `git diff --check` | İzlenen değişikliklerde boşluk hatası yok. |

## Rapor neyi kanıtlar?

Bir README'nin bir betiği çağırması statik kanıttır; betiğin çalıştığını göstermez. Benzer şekilde, onaylanmış bir MCP aracının şeması değişirse yerel karşılaştırma değişikliği bildirir, aracı çağırmaz. Dinamik inceleme başlatmadan reddedilirse terminal ve JSON `not_executed` gösterir. Sınır denetiminden sonra incelemenin kendisi başarısız olabilir: denetimin geçmesi incelemenin tamamlandığı anlamına gelmez. [Rapor regresyonları](../tests/test_mcp_sandbox.py) bu ayrımı sahte backend ile sınar.

## DSE-015 · Ubuntu ARM64 canlı kabulü

Docker Desktop üzerinde üretim ön kontrolündeki imaj sorgusu, `Volumes` alanı olmayan `dragonscan:local` için `linux none`, volume tanımlayan `postgres:16-alpine` için `linux volumes` döndürdü. İki imaj da çalıştırılmadı; bu kontrol yalnız metadata ayrımını doğrular.

2026-11-27 tarihinde tarayıcı Ubuntu ARM64 sanal makinesinin içinde çalıştı: Linux `6.8.0-142-generic`, Docker Engine `29.1.3`, cgroup v2, `runc`, Python `3.12.3`. İncelenen yerel imaj kimliği: `sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c`. `tests/test_mcp_sandbox.py` SHA-256: `e4f4774ccafa4b7fdfb367636158a9b8acb1d4ef0de565bc815f40341523d48e`.

`DRAGONSCAN_TEST_DOCKER_IMAGE` bu imaj kimliğine ayarlandığında [canlı test](../tests/test_mcp_sandbox.py) (`-k live_isolated`) atlanmadan geçti: **`1 passed in 0.36s`**. Test üretim ön kontrolünde dosya ve ağ sınırlarını, kaynak kotalarını ve alt süreç temizliğini sınadı; ardından yalnız projenin zararsız MCP örneğinden metadata aldı. Sonuç bu konfigürasyonla sınırlıdır. [macOS](mcp_macos_isolation.md) ve Windows izole başlatmayı reddeder; diğer Linux konfigürasyonları için sonuç `unknown`.
