Rozwiązanie części C:

* Dołączanie serwera do grupy: Gdy serwer się dołącza, to pliki nowego serwera
  mają większy priorytet. Na początku swojego działania, Wysyła on do wszystkich
  innych węzłów pakiet DEL z nazwa pliku który informując że posiada on nowy
  plik o takiej nazwie i że jeśli ktoś taki posiada, to musi go usunąć.

* Serwer reaguje na pakiety ADD tak samo jak w specyfikacji części A. Jendak po
  pomyślnym przesłaniu pliku powiadamia inne węzły, żeby usunęły pliki o nazwie
  takich samych jak jego nowo przesłany plik. W ten zachowa się tylko jedna
  kopia pliku.

* Po poprawnym otrzymaniu pliku serwer wysyła wiadomość DEL do wszyskich innych
  serwerów w grupie, by usunęli plik o tej samej nazwie, jeśli go posiadają. Ta
  sytuacja nie powinna mieć miejsca zbyt często, co wynika z poprzedniego
  punktu, ale można to zrobić dla pewności. Szczególnie że pakiety UDP mogą
  przepadnąć. Ważne jest to, że ten nowo wysłany plik powinien mieć
  pierwszeństwo nad plikiem który 'uchował' się w nieodpowiadającym na pakiety
  serwerze.

* Serwer odłączający się od grupy próbuje 'ocalić' swoje pliki. W tym celu
  tworzy listę posiadanych przez siebie plików i wysyła polecenie ADD do
  wszyskich serwerów w grupie. Następnie przez połowę czasu 'timeout' serwer
  oczekuje na zgłoszenia innych węzłów. Gdy jeden z nich zadeklaruje możliwość
  przyjęcia pliku, rozpoczyna się połączanie, takie samo jak poczas uploadowania
  pliku z klienta na serwer. Odchodzący węzeł wysyła swój plik po TCP na adres
  węzła który odpowiedział pakieten CAN_ADD. Aby zapewnić to, by plik pozostał w
  jednej kopii, każdy plik wysyłany jest co najwyżej raz. Tzn, że jesli otrzyma
  on wiele odpowiedzi CAN_ADD dla tego samego pliku to odpowiada tylko na
  jedną. Reszta serwerów gotowych do przyjęcia plików poczeka na timeout na
  sockecie i uzna że wysyłanie się nie udało. Pliki nie będą mogły zostać
  przesłane, gdy w sieci nie ma innych serwerów, lub żaden inny węzeł nie
  przyjmie jakiegoś pliku (na przykład z powodu braku miejsca). Ale podczas
  wyjścia z programu zgodnego ze specyfikacją jest duża szansa na uratowanie
  większości danych i przesłanie ich do innych serwerów. Pliki które zostały
  przesłane skutecznie przy wychodzeniu z programu zostaną usunięte z tysku
  wyłączającego się węzła. Gdy węzeł wstanie ponownie, będzie miał tylko pliki,
  których nie udało się wysłać.

Wady:

Jedyna, ale za to oczywista wada jest w sytuacji, gdy dwa pliki w tym samym
momencie zakończą pobieranie pliku i wyślą komunikat DEL, nawzajem go odbierając
i usuwając swoje pliki. W ten sposób plik nie zapisze się na żadnym z
serwerów. Jest to sytuacja dosyć mało prawdopodobna (mi nie udało się jej
odtworzć), ale jak najbardziej możliwa.

Niezaimplementowane rozwiązanie (za to wydaje się pomysłowe):

Głównym problemem jest komunikacja po UPD i fakt, że gdy dwie maszyny w tym
samym czasie wyślą komunikat DEL to nie można ustalić, kto powinien usunąć plik
a kto zostawić. Jednym sposobem rozwiązania tego problemu jest wysłanie czasu w
nanosekundach od 01.01.1970 w którym momencie plik został przesłany. Ale i to
rozwiązanie ma wady, poniważ wyjątkowo źle działa w środowiku gdzie zegary
maszyn nie są zsynchronizowane. Rozwiązaniem wydaje sie być wybranie mastera,
serwera-lidera, do którego kierowane byłyby wszystkie komunikaty dotyczące
zuploadowania jakiegoś pliku na pewien węzeł i to on zajmowałby się
powiadamieniem innych węzełów jakie pliki mają usunąć (tzn master po otrzymaniu
od węzła A informacji o uploadzie pliku foo.txt na węzeł A) wysyłałby do węzła B
informację (na jego unicast), że jego plik foo.txt jest przedawniony i ma zostać
usunięty). Niestety zaimplementowanie algorytmu znajdowania lidera w grupie
węzłów nie jest proste. Węzły musiałyby potrafić np. wybrać między sobą nowego
lidera, gdy stary przestanie odpowiadać, albo padnie.

Dla uproszczenia przyjmijmy że liderem jak węzeł o najmniejszym (liczbowo)
adresie IP. Węzły regularnie wykonują HELLO i znajdują taki węzeł, a następnie
wysyłają mu swój pakiet MY_LIST ze wszyskimi zaindeksowanymi plikami. Gdy na tym
etapie jakiś plik się powtórzy master do wszyskich węzłów posiadających ten plik
wysyła komendę DEL, by pozbyć się duplikatów. Wszystkie serwery działają zgodnie
ze specyfikacją A, a podczas umierania próbują przesłać byle gdzie swoje pliki,
jak opisano wyżej. Po udanym przesłaniu pliku (czyli po udanej odpowiedzi na
pakiet CAN_ADD i poprawnym wysłaniu całego pliku przez TCP) informują mastera o
tym, że otrzymali taki plik pakietem [SIMPL]("SYNC_GOT", {nazwa pliku}), który
oznacza, że na węzeł wysyłający pakiet został zuploadowany plik {nazwa
pliku}. Oczywiście master nie wysyła tego pakietu sam do siebie, bo nie
musi. Poniważ master posiada listę plików we wszyskich węzłach wie, czy ktoś nie
przechowywał tego pliku wcześniej i jeśli tak było, to wysyła do tego kogoś
(znów, na unicast, ta wiadomość nie jest rozesłana do wszyskich, więc jest dużo
lepiej) pakiet DEL z informacją, jaki plik ma usunąć. Niestety, to rozwiązanie
jest też znacznie bardziej skomplikowane i mimo że wydaje się fajnym pomysłem,
nie zostało w żaden sposób przeze mnie zaimplementowane.
