Rozwiązanie części C:

* Dołączanie serwera do grupy: Gdy serwer się dołącza, po indeksowaniu plików
  wysyła zapytanie do innych zsynchronizowanych serwerów w tej grupie
  sprawdzając czy ktoś nie ma pliku o takiej samej nazwie jak on. Jeśli takowy
  jest, to nowy serwer musi usunąć swój plik, żeby nie było duplikatu.

* Po otrzymaniu prośby o dodanie plików (która kierowana jest na unicast jednego
  węzła serwerowego), musi on upewnić się, że żaden z innych węzłów nie zawiera
  pliku o tej nazwie. Jeśli tak jest, to serwer nie przyjmuje tego pliku
  odpowiadając standardowym pakietem NO_WAY. Oczywiście w UDP zawsze może
  nastąpić sytuacja, że pewne pakiety udp przepadną i serwer który dostanie
  polecenie ADD nie będzie wiedział o tym, że inny serwer posiada takowy plik.

* Po poprawnym otrzymaniu pliku serwer wysyła wiadomość DEL do wszyskich innych
  serwerów w grupie, by usunęli plik o tej samej nazwie, jeśli go posiadają. Ta
  sytuacja nie powinna mieć miejsca zbyt często, co wynika z poprzedniego
  punktu, ale można to zrobić dla pewności. Szczególnie że pakiety UDP mogą
  przepadnąć. Ważne jest to, że ten nowo wysłany plik powinien mieć
  pierwszeństwo nad plikiem który 'uchował' się w nieodpowiadającym na pakiety
  serwerze.

* Serwer odłączający się od grupy próbuje 'ocalić' swoje pliki. W tym celu
  tworzy listę posiadanych przez siebie plików i wysyła polecenie ADD do
  wszyskich serwerów w grupie. Następnie przez 'timeout' sekund serwer oczekuje
  na zgłoszenia innych węzłów. Gdy jeden z nich zadeklaruje możliwość przyjęcia
  pliku, rozpoczyna się połączanie, takie samo jak poczas uploadowania pliku z
  klienta na serwer. Odchodzący węzeł wysyła swój plik po TCP na adres węzła
  który odpowiedział pakieten CAN_ADD. Aby zapewnić to, by plik pozostał w
  jednej kopii, każdy plik wysyłany jest co najwyżej raz. Tzn, że jesli otrzyma
  on wiele odpowiedzi CAN_ADD dla tego samego pliku to odpowiada tylko na
  jedną. Oczywiście, jeśli proces serwera padnia, albo zostanie zabity, pliki
  przepadają. Przepadną również, gdy w sieci nie ma innych serwerów. Ale podczas
  wyjścia z programu zgodnego ze specyfikacją jest duża szansa na uratowanie
  większości danych i przesłanie ich do innych serwerów.
