# LaTeX (IEEE) váz a FIDO2 projekthez

Ez a mappa egy IEEE-stílusú cikk sablont tartalmaz. A bekezdések szándékosan üresek.

## Struktúra
```
docs/
  latex/
    main.tex
    figures/
    bib/
      references.bib
```

## Fordítás
### Lokálisan
- Ajánlott: `latexmk` használata XeLaTeX-szel.
- Parancs:
  ```bash
  latexmk -xelatex -interaction=nonstopmode -file-line-error docs/latex/main.tex
  ```
- A PDF a `docs/latex/main.pdf` néven jön létre.

### GitHub Actions
A repo tartalmaz egy workflow-t (`.github/workflows/latex.yml`), amely minden push/PR esetén lefordítja a PDF-et és artefaktként elmenti.

## Hivatkozások
- A hivatkozásokat a `docs/latex/bib/references.bib` fájlba add hozzá (BibTeX).
