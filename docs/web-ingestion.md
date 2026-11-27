# Yerel web girdisi ve alan adı kanıtı

`dragonscan scan-web DOSYA` kaydedilmiş bir girdiyi inceler. Tarayıcı açmaz, arama yapmaz, betik çalıştırmaz ve bağlantı izlemez. `dragonscan domain-evidence ALAN` ayrı bir komuttur: yalnızca operatörün yazdığı alan adını işler. İki komut da varsayılan olarak çevrimdışıdır; `scan-web` çıktısındaki alan adları sorgu kuyruğuna alınmaz.

## Bir kaydı inceleme

```console
dragonscan scan-web page.html
dragonscan scan-web README.md
dragonscan scan-web search.json
```

HTML için `.html` ve `.htm`; README için `README`, `README.md`, `README.markdown` ve `README.txt` desteklenir. Kayıtlı arama için `.json` dosyası şu biçimdedir:

```json
{"results":[{"title":"Kurulum rehberi","url":"https://docs.example.net/guide","snippet":"Kullanım notları."}]}
```

Her sonuçta `url`, `title` veya `snippet` alanlarından en az biri gerekir. Başlık ve özet ayrı ayrı taranır; iki farklı sonuçtan bir saldırı yolu oluşturulmaz. `url` hedefi ziyaret edilmez. HTTP(S) bağlantılarından yalnız DNS adı raporlanır; kullanıcı bilgisi, URL yolu, sorgu ve parça rapora eklenmez. Adres sabitleri ve göreli URL'ler alan adı kanıtı değildir.

JSON çıktısındaki `source` ve `sha256`, **orijinal dosyayı** tanımlar. HTML/README bulgularında `location.line` 1'den başlar. HTML'deki `hidden`, `aria-hidden=true`, `template`, satır içi `display:none` / `visibility:hidden` ve yorumlar metin olarak incelenir. `hidden` bağlamı, görünmezliğe işaret eden bir nitelik bulunduğunu belirtir; sayfanın bir tarayıcıda nasıl göründüğünü kanıtlamaz. Öznitelikteki URL için satır, açılış etiketinin başlangıcıdır. Arama sonuçlarında `location.pointer`, örneğin `/results/0/snippet`, doğrudan kaynak alanını gösterir. Dosya düzeyindeki bir bulgu için satır bilinmeyebilir. Bulgu kimliği, başlığı, etki şiddeti ve güven düzeyi statik tarayıcıdan gelir; hedefte bir eylem gerçekleştiği anlamına gelmez.

**Sınırlar:** Her girdi en fazla 1 MiB'lık, UTF-8 kodlu normal bir dosya olmalıdır; dosya olarak sembolik bağlantı kabul edilmez. En fazla 32 arama sonucu, görünüm başına 8.192 satır ve satır başına 16.384 karakter kabul edilir. Desteklenmeyen biçim veya bu girdi sınırlarının aşılması hatadır. Çıktı 256 alan adı gözlemi ve 256 bulguyla sınırlıdır; kesilirse `coverage: partial` döner. `complete` yalnızca desteklenen metin görünümünün tarandığı anlamına gelir. Harici CSS, JavaScript ile oluşturulan DOM, `script`/`style` gövdeleri ve bilinmeyen arama alanları incelenmez. TLS araya girme ve otomatik tarama yoktur. Başarılı JSON üretimi çıkış kodu 0'dır; bu bir güvenlik/politika geçiş kararı değildir.

## Alan adı, DNS ve kayıt geçmişi

```console
dragonscan domain-evidence www.example.com
dragonscan domain-evidence www.example.com --dns-record dns.json --history previous.json
dragonscan domain-evidence docs.example.co.uk --psl public_suffix_list.dat
```

İlk komut DNS bile sorgulamaz. Kabul edilen adlar IDNA ASCII biçimine dönüştürülür; kayıplı dönüşümler, IP adresleri, URL ve kullanıcı bilgileri reddedilir. Yerleşik kayıt sınırları `.com` ve `.net` içindir. Diğer sonekler için güvenilen bir yerel Public Suffix List (PSL) dosyası verilebilir. ICANN bölümünde en uzun eşleşme, joker ve istisna kuralları uygulanır. Özel barındırma sonekleri registry kaydı olarak yorumlanmaz. Eşleşmeyen bir sınır tahmin edilmez (`registrable_domain: null`). PSL dosyası indirilmez veya güncellenmez.

`--dns-record` tam **ana bilgisayar adı** için önceden kaydedilmiş bir DNS gözlemidir:

```json
{"domain":"www.example.com","rcode":"NXDOMAIN","observed_at":"2025-03-20T12:00:00Z"}
```

`NXDOMAIN`, `NOERROR`, `SERVFAIL` ve `TIMEOUT` ayrıdır. NXDOMAIN, o ada gözlem anında DNS cevabı bulunmadığına ilişkin operatör kaydıdır; kayıt edilebilirliği veya kötü niyeti göstermez. `NOERROR` da bir adres kaydının bulunduğunu garanti etmez.

`--history` **aynı kaydedilebilir alan adı** için operatörün güvendiği geçmiş kayıttır:

```json
{"domain":"example.com","observed_at":"2020-02-01T12:00:00Z","registered_at":"2015-07-03T10:30:00Z"}
```

Geçmiş tarih, bu dosyanın gözlem tarihinden sonra olamaz. Yanlış domain, yinelenen JSON anahtarı veya geçersiz tarih hata verir. Çıktı yerel kanıtın dosya yolunu ve SHA-256 özetini korur; özet, dosyanın kaynağını doğrulamaz.

### Yalnız açık onayla RDAP

`dragonscan domain-evidence www.example.com --rdap` yalnız **`example.com`** adını yetkili kayıt kuruluşuna gönderir. Bu bayrak olmadan hiç ağ erişimi yapılmaz. Desteklenen sabit uç noktalar `.com` ve `.net` için `rdap.verisign.com` üzerindedir. Başka sonek için sonuç `unsupported` olur; başka bir sağlayıcı denenmez. Hedef sitenin kendisine DNS veya HTTP isteği gönderilmez. Arama geçmişi, yakalanmış içerik, URL yolu ve yerel dosyalar kuruluşa gönderilmez.

Kayıt kuruluşuna giden HTTPS bağlantısı genel bir IP'ye sabitlenir ve TLS sertifikası doğrulanır. İzin verilen tek yönlendirme aynı kayıt kaynağıdır (isteğe bağlı son `/`); her adımda otorite, hedef yol ve çözümlenen adresler yeniden denetlenir. Aktarım 256 KiB ve üç yönlendirmeyle sınırlıdır. Ağ işleminin zaman bütçesi 30 saniye, DNS beklemesi ve soket zaman aşımı en çok 8 saniyedir. Geç kalan sistem DNS çözümlemesi tamamlanabilir ancak bağlantı açamaz.

| Kanıt | Yorum |
|---|---|
| `rdap.registered` | Yetkili yanıtın nesne tipi ve alan adı eşleşti. Kişi veya kurum kimliği iddiası yoktur. |
| `rdap.unregistered` | Yetkili uç nokta RDAP biçiminde 404 döndürdü; satın alınabilirlik garantisi değildir. |
| `rdap.timeout` / `unknown` | Süre doldu veya yanıt doğrulanamadı. Genel HTTP 404, hata sayfası, özel IP ve başka alana yönlendirme kayıt yokluğunu kanıtlamaz. |
| `history.registration_epoch_changed` | Güncel kayıt tarihi, aynı alan için güvenilen önceki gözlemden sonradır. Kayıt dönemi farklıdır; sahibin kimliğinin değiştiği kanıtlanmaz. |
| `history.same_registration_epoch` / `not_comparable` | Kayıt tarihleri aynı ya da yeterli karşılaştırma kanıtı yoktur. Güncel RDAP tek başına geçmiş değildir. |

Tablodaki gösterim bölüm ve durum adını birleştirir: örneğin `{ "rdap": { "status": "registered" } }`. Sorgu istenmezse RDAP `not_requested`, yerel geçmiş veya DNS kaydı verilmezse ilgili bölüm `not_supplied` olur. Bu kanıtlar itibarı puanlamaz ve tek başına alan adını engellemez.
