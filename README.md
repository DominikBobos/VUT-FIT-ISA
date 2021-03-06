# 17/20b

# VUT-FIT-ISA

## Popis:
Vytvořte komunikující aplikaci podle konkrétní vybrané specifikace pomocí síťové knihovny BSD sockets (pokud není ve variantě zadání uvedeno jinak). Projekt bude vypracován v jazyce C/C++. Pokud individuální zadání nespecifikuje vlastní referenční systém, musí být projekt přeložitelný a spustitelný na serveru merlin.fit.vutbr.cz pod operačním systémem GNU/Linux. Program by však měl být přenositelný. Hodnocení projektů může probíhat na jiném počítači s nainstalovaným OS GNU/Linux, včetně jiných architektur než Intel/AMD, jiných distribucí, jiných verzí knihoven apod. Pokud vyžadujete minimální verzi knihovny (dostupnou na serveru merlin), jasně tuto skutečnost označte v dokumentaci a README.

Vypracovaný projekt uložený v archívu .tar a se jménem xlogin00.tar odevzdejte elektronicky přes IS. Soubor nekomprimujte.
Termín odevzdání je 18.11.2020 (hard deadline). Odevzdání e-mailem po uplynutí termínu, dodatečné opravy či doplnění kódu není možné.
Odevzdaný projekt musí obsahovat:
soubor se zdrojovým kódem (dodržujte jména souborů uvedená v konkrétním zadání),
funkční Makefile pro překlad zdrojového souboru,
dokumentaci (soubor manual.pdf), která bude obsahovat uvedení do problematiky, návrhu aplikace, popis implementace, základní informace o programu, návod na použití. V dokumentaci se očekává následující: titulní strana, obsah, logické strukturování textu, přehled nastudovaných informací z literatury, popis zajímavějších pasáží implementace, použití vytvořených programů a literatura.
soubor README obsahující krátký textový popis programu s případnými rozšířeními/omezeními, příklad spuštění a seznam odevzdaných souborů,
další požadované soubory podle konkrétního typu zadání. 
Pokud v projektu nestihnete implementovat všechny požadované vlastnosti, je nutné veškerá omezení jasně uvést v dokumentaci a v souboru README.
Co není v zadání jednoznačně uvedeno, můžete implementovat podle svého vlastního výběru. Zvolené řešení popište v dokumentaci.
Při řešení projektu respektujte zvyklosti zavedené v OS unixového typu (jako je například formát textového souboru).
Vytvořené programy by měly být použitelné a smysluplné, řádně komentované a formátované a členěné do funkcí a modulů. Program by měl obsahovat nápovědu informující uživatele o činnosti programu a jeho parametrech. Případné chyby budou intuitivně popisovány uživateli.
Aplikace nesmí v žádném případě skončit s chybou SEGMENTATION FAULT ani jiným násilným systémovým ukončením (např. dělení nulou).
Pokud přejímáte krátké pasáže zdrojových kódů z různých tutoriálů či příkladů z Internetu (ne mezi sebou), tak je nutné vyznačit tyto sekce a jejich autory dle licenčních podmínek, kterými se distribuce daných zdrojových kódů řídí. V případě nedodržení bude na projekt nahlíženo jako na plagiát.
Konzultace k projektu podává vyučující, který zadání vypsal.
Sledujte fórum k projektu, kde se může objevit dovysvětlení či upřesnění týkající se zadání.
Před odevzdáním zkontrolujte, zda jste dodrželi všechna jména souborů požadovaná ve společné části zadání i v zadání pro konkrétní projekt. Zkontrolujte, zda je projekt přeložitelný.
Hodnocení projektu:
Maximální počet bodů za projekt je 20 bodů.
Maximálně 15 bodů za plně funkční aplikaci.
Maximálně 5 bodů za dokumentaci. Dokumentace se hodnotí pouze v případě funkčního kódu. Pokud kód není odevzdán nebo nefunguje podle zadání, dokumentace se nehodnotí.
Příklad kriterií pro hodnocení projektů:
nepřehledný, nekomentovaný zdrojový text: až -7 bodů
nefunkční či chybějící Makefile: až -4 body
nekvalitní či chybějící dokumentace: až -5 bodů
nedodržení formátu vstupu/výstupu či konfigurace: -10 body
odevzdaný soubor nelze přeložit, spustit a odzkoušet: 0 bodů
odevzdáno po termínu: 0 bodů
nedodržení zadání: 0 bodů
nefunkční kód: 0 bodů
opsáno: 0 bodů (pro všechny, kdo mají stejný kód), návrh na zahájení disciplinárního řízení.

## Popis:
V rámci projektu vytvořte jednoduchý nástroj, který zpracuje pcap soubor a zobrazí informace o SSL spojení.
Spuštění aplikace

sslsniff [-r <file>] [-i interface]

Pořadí parametrů je libovolné. Popis parametrů:

-r: Soubor se síťovým provozem ve formátu pcapng
-i: Síťové rozhraní, na kterém program naslouchá
Výstup aplikace

Na standardní výstup vypište informace o navštívené SSL službě v následujícím formátu: <timestamp>,<client ip><client port>,<server ip><SNI>,<bytes>,<packets>,<duration sec>

Příklad výstupu:

2020-09-22 14:12:47.838588,2a00:1028:83a0:65aa:21ae:c290:d8bd:4b66,51416,2001:67c:1220:809::93e5:91a,www.fit.vut.cz,99421,120,0.175

...

Upřesnění zadání

Při vytváření programu je povoleno použít hlavičkové soubory pro práci se sokety a další obvyklé funkce používané v síťovém prostředí (jako je netinet/*, sys/*, arpa/* apod.), knihovny pro práci s vlákny (pthread), pakety (pcap), signály, časem, stejně jako standardní knihovnu jazyka C (varianty ISO/ANSI i POSIX), C++ a STL. 
Předpokládejte soubor ve formátu pcapng.
Při odposlechu na síťovém rozhraní zpracovávejte a vypisujte informace o spojeních, dokud nebude program ukončen.
Dokumentace:

Soubor Readme z obecného zadání nahraďte souborem sslsniff.1 ve formátu a syntaxi manuálové stránky - viz https://liw.fi/manpages/ 

Dokumentaci ve formátu pdf vytvořte dle pokynu v obecném zadání.

Doplňující informace k zadání

Před odevzdáním projektu si důkladně pročtěte společné zadání pro všechny projekty.
Jakékoliv rozšíření nezapomeňte zdůraznit v manuálové stránce a v dokumentaci. Není však možné získat více bodů, než je stanovené maximum.
Program se musí vypořádat s chybnými vstupy.
Veškeré chybové výpisy vypisujte srozumitelně na standardní chybový výstup.
Pokud máte pocit, že v zadání není něco specifikováno, popište v dokumentaci vámi zvolené řešení a zdůvodněte, proč jste jej vybrali.
Pište robustní aplikace, které budou vstřícné k drobným odchylkám od specifikace.
Při řešení projektu uplatněte znalosti získané v dřívějších kurzech týkající se jak zdrojového kódu (formátování, komentáře), pojmenování souborů, tak vstřícnosti programu k uživateli.
Referenční prostředí pro překlad a testování

Program by měl být přenositelný. Referenční prostředí pro překlad bude server merlin.fit.vutbr.cz (program zde musí být přeložitelný). Vlastní testování může probíhat na jiném počítači s nainstalovaným OS GNU/Linux, včetně jiných architektur než Intel/AMD, jiných distribucí, jiných verzí knihoven apod. Pokud vyžadujete minimální verzi knihovny, jasně tuto skutečnost označte v dokumentaci a v manuálové stránce. Pro případné testování vaší aplikace lze využít virtuální stroj dostupný ke stažení https://vutbr-my.sharepoint.com/:u:/g/personal/xvesel38_vutbr_cz/Ecthn_lpXplAuJROhs8UeEEB2nEf6KN_1dDHLN8H_ww-9A?e=LlQILE, informace k nainstalovaným balíčkům a výchozím nastavení je na https://github.com/nesfit/PDS-VM. 
