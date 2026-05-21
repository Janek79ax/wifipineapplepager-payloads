# RTL-SDR 433 Sniffer

Pasywny sniffer urządzeń ISM 433 MHz (czujniki pogodowe, piloty bram, termometry, alarmy)
z wykorzystaniem dongla RTL-SDR i narzędzia `rtl_433`. Zdekodowane odczyty wyświetlane są
na żywo na ekranie pagera.

## Wymagania sprzętowe

- **Dongle RTL-SDR USB** (chipset RTL2832U / RTL2838) podłączony do portu USB pagera.
- **Antena 433 MHz** dostrojona (dipol, helisa, "rubber duck" itp.). Antena domyślna z zestawu
  RTL-SDR często łapie sygnały z odległości kilkudziesięciu metrów.
- Połączenie z internetem **przy pierwszym uruchomieniu** (do `opkg install`).

## Co robi payload

1. **Faza instalacyjna (idempotentna)** — przy pierwszym uruchomieniu sprawdza, czy
   `librtlsdr` i `rtl_433` są zainstalowane. Jeśli nie, pyta o zgodę i wykonuje:
   ```
   opkg update
   opkg install librtlsdr
   opkg install rtl_433
   ```
2. **Sprawdzenie dongla** — `lsusb` szuka chipsetu RTL2832/RTL2838. Brak nie zatrzymuje
   payloadu (niektóre stare dongle nie są rozpoznawane), tylko wyświetla ostrzeżenie.
3. **Sniffing** — uruchamia `rtl_433` w tle i parsuje jego standardowy output linia po linii.
   Każdy odczyt zostaje wyświetlony pokolorowany:
   - szary `[time]`
   - zielony `model: <nazwa>` (+ krótka wibracja jako feedback)
   - cyan `T:` / `H:` (temperatura, wilgotność)
   - żółty `Bat:` (status baterii)
   - białe pozostałe pola
4. **Zapis do loot** — pełny tekstowy log każdej sesji jest zapisywany do
   `/root/loot/rtl_433/rtl_433_<YYYYMMDD_HHMMSS>.log`.

## Wyjście z payloadu

Po prostu wyjdź z payloadu na pagerze (przycisk B / standardowe wyjście) — `trap cleanup`
łapie sygnał, zabija proces `rtl_433` (odpowiednik `Ctrl-C` z linii poleceń) i czyści temp.

## Przykładowy output na ekranie

```
[2026-05-21 04:42:21]
model: Nexus-TH
House Code: 71
Ch: 1
Bat: 1
T: 29.50 C
H: 40 %
```

## Uwagi

- `rtl_433` domyślnie nasłuchuje na **433.92 MHz** ze wszystkimi wbudowanymi dekoderami.
  Jeśli chcesz użyć innej częstotliwości lub dekodera, zedytuj wywołanie `rtl_433` w
  `payload.sh` (np. `rtl_433 -f 868M -R 19`).
- Jednocześnie tylko jedna aplikacja może używać dongla RTL-SDR. Upewnij się, że żaden
  inny payload korzystający z SDR nie jest aktywny.
