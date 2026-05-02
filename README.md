# NetGuard Security Hub 🛡️

NetGuard, yerel ağınızdaki cihazları tarayan, zafiyet analizi yapan ve güvenlik skorunuzu hesaplayan asenkron bir ağ tarayıcısıdır.

## 🚀 Başlangıç

Projeyi çalıştırmak için aşağıdaki adımları izleyin:

### 1. Gereksinimler
- **Python 3.8+**
- **Npcap (Windows için):** Scapy'nin ARP taraması yapabilmesi için [npcap.com](https://npcap.com/) adresinden Npcap'i "Install Npcap in WinPcap API-compatible Mode" seçeneğiyle yüklemeniz gerekir.
- **Yönetici Hakları:** Ağ kartına erişim için terminali **Yönetici (Administrator)** olarak çalıştırmanız önerilir.

### 2. Bağımlılıkları Kurun
Terminali proje dizininde açın ve şunu çalıştırın:
```bash
pip install -r requirements.txt
```

### 3. Uygulamayı Başlatın
```bash
python main.py
```

### 4. Arayüze Erişin
Tarayıcınızı açın ve şu adrese gidin:
[http://localhost:8001](http://localhost:8001)

---

## 🛠️ Özellikler
- **Asenkron Tarama:** Arka planda donma yapmadan hızlı ağ keşfi.
- **Zafiyet Analizi:** NVD (National Vulnerability Database) entegrasyonu ile cihazlardaki açıkları tespit etme.
- **Filtreleme & Geçmiş:** Gelişmiş arama ve sayfalama desteği ile geçmiş taramaları inceleme.
- **Raporlama:** Tarama sonuçlarını CSV veya JSON formatında dışa aktarma.
- **Zamanlanmış Taramalar:** Belirlediğiniz aralıklarla otomatik ağ denetimi.

## 🧪 Testler
Sistemin kararlılığını kontrol etmek için:
```bash
python -m pytest tests/test_api.py -v
```
