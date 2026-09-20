# Home WiFi Watch

Pasywny detektor zmian otoczenia Wi-Fi dla Hak5 WiFi Pineapple Pager.
Odbiera wyłącznie beacony przez `tcpdump` na istniejącym interfejsie monitorującym.
Nie wysyła probe requestów, deauthów ani innych ramek. Nie uruchamia AP,
nie łączy się z obserwowanymi sieciami i nie zapisuje ruchu użytkowników.

## Instalacja i uruchomienie

1. Skopiuj cały katalog `home_wifi_watch` do
   `/mmc/root/payloads/user/reconnaissance/` na Pagerze.
2. Wymagane: Bash, `tcpdump`, `iw`, Python 3 ze standardowymi modułami
   (`json`, `fcntl`, `threading`, `selectors`, `subprocess`). Jeśli brakuje Pythona,
   zainstaluj pełny pakiet `python3` przez menedżer pakietów Pagera; payload nie
   instaluje zależności automatycznie.
3. Domyślnie payload sam wybiera interfejs, którego rzeczywisty typ według
   `iw dev` to `monitor`. Opcjonalnie ustaw `INTERFACE` w `config.sh`, np.
   `INTERFACE="wlan1mon"`. Nazwa nie wystarcza: wskazany interfejs nadal musi
   mieć typ `monitor`. Do obserwacji wielu kanałów uruchom wcześniej pasywny
   Recon z przełączaniem kanałów na tym radiu.
4. Uruchom **Home WiFi Watch** z menu payloadów. Pierwsze uruchomienie uczy
   otoczenia przez 60 sekund. W tym czasie korzystaj ze znanego otoczenia.
   Dźwięk/wibracja oraz żółty wpis w logu sygnalizują alarm.
5. Zatrzymaj przez standardowe sterowanie uruchomionym payloadem. Zakończenie
   procesu sprząta tylko własny `tcpdump` i gasi LED.

Pager może wykonywać tymczasową kopię skryptu jako `/tmp/payload.sh`. Payload
uwzględnia to i szuka `watch.py` oraz `config.sh` w bieżącym katalogu i w
standardowych lokalizacjach `/mmc/root/payloads/` oraz `/root/payloads/`.

Payload nie zmienia kanału ani ustawień PineAP. Jeśli radio stoi na jednym
kanale, widzi tylko ten kanał. Nie zmienia też trybu innych uruchomionych
funkcji urządzenia: pełna pasywność Pagera wymaga wyłączenia innych funkcji
nadających. Czas wykrycia zależy od powrotu radia na kanał danego AP.

Jeżeli payload zgłosi brak interfejsu monitorującego, uruchom pasywny Recon i
spróbuj ponownie. W logu pokaże interfejsy i ich rzeczywiste tryby wykryte przez
`iw`. Sam nie tworzy interfejsu monitorującego, bo taka operacja mogłaby zmienić
stan radia używanego przez PineAP lub połączenie zarządzające.

## Reguły wykrywania

- **Próg:** RSSI ≥ **−80 dBm**, włącznie z −80. Brak RSSI, 0 dBm i ramki
  oznaczone błędnym FCS są pomijane.
- **Potwierdzenie:** ten sam BSSID, SSID i profil zabezpieczeń musi być
  odebrany z mocnym sygnałem w **3 różnych sekundach w ciągu 15 sekund**.
  Słabsza obserwacja tego profilu zeruje potwierdzenie. Seria beaconów w jednej
  sekundzie nie wystarcza. Są to trzy obserwacje, nie wymóg ciągłej widoczności.
- **Minutowa pamięć obecności:** AP staje się kandydatem po pierwszym
  zobaczeniu lub po ≥60 s bez jego beaconów. Krótsza nieobecność nie uruchamia
  kolejnego alarmu obecności. Również słabe beacony odświeżają ostatnią obecność.
  Kandydat oczekuje na potwierdzenie mocnym sygnałem.
- **NEW_AP:** potwierdzony kandydat spoza zapisanej bazy.
- **RETURNED_AP:** analogiczny powrót AP z bazy po przynajmniej minucie ciszy.
- **SECURITY_CHANGED:** inny profil zabezpieczeń znanego SSID/BSSID, także
  na nowym BSSID dla znanego SSID. Porównywane są RSN/WPA, szyfr grupowy,
  zestawy szyfrów i AKM oraz bity PMF. `OPEN` i `PRIVACY_UNKNOWN` są odrębne;
  sama flaga Privacy nie jest dowodem na WEP. PMKID i liczniki replay nie
  wywołują zmian. Szczegóły profilu są zapisane w JSON logu.
- **BSSID_CHANGED:** znany SSID pojawia się na innym BSSID, a poprzedniego
  BSSID nie zaobserwowano w ostatniej minucie.
- **SSID_COPY:** dodatkowy BSSID dla tego samego SSID, gdy inny jest świeżo
  widoczny. Porównanie obejmuje bazę i aktualnie potwierdzone obserwacje.
- **SSID_CHANGED:** znany BSSID zaczyna ogłaszać nowy niepusty SSID.
- **EVIL_TWIN_CERTAIN:** potwierdzony, niezaufany profil nadaje SSID będący
  dokładnie znanym SSID z jednym dodatkowym znakiem Unicode na końcu. Obejmuje
  to niewidoczny `U+200B` (`zero-width space`) używany do uniknięcia grupowania
  sieci przez telefon. Ta reguła zastępuje dla danego wykrycia ogólne alarmy
  `NEW_AP`, `BSSID_CHANGED`, `SSID_COPY` i `SSID_CHANGED`, wyświetla czerwony
  alert oraz uruchamia mocniejszą wibrację. Widoczny pojedynczy znak również
  spełnia tę politykę. Wariant już zapisany w bazie jako zaufany nie otrzymuje
  tej klasyfikacji (może nadal wywołać zwykły `RETURNED_AP` po minucie ciszy).
- Ta sama zmiana ponawia alarm najwyżej raz na **300 sekund**. W przypadku
  alarmów obecności potrzebne jest dodatkowo ponowne zniknięcie na minutę.
  Zmiana zabezpieczeń lub kopia SSID może przypominać o sobie co 300 s,
  dopóki nadal jest potwierdzana. Jedna obserwacja może mieć kilka przyczyn alarmu.

Pierwsza minuta tworzy bazę wyłącznie z potwierdzonych mocnych profili.
Legalne AP mesh/wielopasmowe widoczne podczas uczenia są zapamiętywane osobno.
Przy kolejnych uruchomieniach baza pozostaje stała; pierwsza minuta rozgrzewa
historię obecności, a porównywanie zabezpieczeń i tożsamości działa od razu.
Podejrzane zmiany nie są automatycznie dopisywane do bazy.
Ukryte SSID mają pustą nazwę i nie są porównywane ze sobą jako kopie.

**Ostrzeżenie o możliwym Evil Twin jest heurystyką**, nie potwierdzeniem ataku.
Mesh, repeater, wymiana routera lub AP pominięty podczas uczenia mogą dać taki
sam objaw. Atak kopiujący jednocześnie SSID, BSSID i zabezpieczenia może być
niewykrywalny. Nie są rozwijane profile nieemitowanych BSSID z elementu Multiple
BSSID ani rozszerzenia RSNXE. Payload analizuje bezpośrednio odebrane beacony.

## Pamięć i konfiguracja

`config.sh` zawiera próg, okno/liczbę potwierdzeń, odstęp alarmów, interfejs i
katalog danych. Jeśli radio rzadko wraca na kanał, zwiększ `CONFIRM_WINDOW`
(maksymalnie 60 s) lub dopasuj plan kanałów Recon.

Dane są domyślnie w `/root/loot/home_wifi_watch/`. Jeżeli ten katalog nie jest
zapisywalny, payload automatycznie używa katalogu `data` obok `payload.sh` na
pamięci `/mmc` i informuje o tym w logu:

- `baseline.json`: trwała baza, zapis atomowy po zakończeniu uczenia.
- `events.jsonl`: alarmy z datą, BSSID, SSID w hex, RSSI i profilem zabezpieczeń.
- `events.previous.jsonl`: poprzedni log; rotacja przy około 2 MiB.
- `runtime.log`: bieżąca diagnostyka Pythona i `tcpdump`; nadpisywana przy starcie.
- `watch.lock`: blokada przed równoległym uruchomieniem w tym samym katalogu.

Aby nauczyć otoczenie ponownie, zatrzymaj payload, przenieś `baseline.json`
np. do `baseline.backup.json` i uruchom ponownie. To zastąpi punkt odniesienia
obecnie widocznym otoczeniem. Pusta minuta uczenia nie zapisuje bazy i kończy
się błędem. Przy zapisanej bazie brak prawidłowych beaconów przez minutę daje
komunikat diagnostyczny. Nie gwarantuje to wykrycia awarii pojedynczego kanału.

SSID pozostaje surowymi bajtami w kluczu porównania, a w UI jest escapowany.
Ramki nie trafiają na dysk. Historia bieżąca jest w RAM; restart zeruje czasy
obecności i ograniczania alarmów. Opóźnione powiadomienia UI mają ograniczoną
kolejkę: przy zalewie część dźwięków/wpisów UI może zostać pominięta, ale
wszystkie wygenerowane zdarzenia pozostają w rotowanym logu.

## Weryfikacja

Na komputerze w katalogu repozytorium:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s library/user/reconnaissance/home_wifi_watch -p 'test_*.py' -v
bash -n library/user/reconnaissance/home_wifi_watch/payload.sh library/user/reconnaissance/home_wifi_watch/config.sh
```

Testy obejmują uczenie/restart, próg, flapping, minutową nieobecność, cooldown,
mesh, zmiany SSID/szyfrowania, ukryte SSID, ramki z FCS, uszkodzone ramki,
alignment radiotap i częściowe odczyty PCAP. Nie zastępują testu na urządzeniu.
Na Pagerze sprawdź własnym dodatkowym AP: nowy SSID, kopię SSID i zmianę
WPA→Open, potem zatrzymanie payloadu oraz ponowne uruchomienie z zapisaną bazą.

Formaty referencyjne: [Radiotap](https://www.radiotap.org/),
[RSSI w dBm](https://www.radiotap.org/fields/Antenna%20signal.html),
[libpcap savefile](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in).
