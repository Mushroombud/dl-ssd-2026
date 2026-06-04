# RAG Retrieval Testset Summary

- cases: 3
- dense: False
- reranker: False
- cases_with_hits: 3

## Top Hits

### tc1.json (pass)
- target: Properties SessionManager status=SUCCESS
- 1. `opal/4.1.1.1.txt` score=0.0315 title=4.1.1.1 Properties (M)
- 2. `opal/4.2.1.8.txt` score=0.0261 title=4.2.1.8 C_PIN (M)
- 3. `_pdf_enrichment/opal/details/4.1.1.1.md` score=0.0237 title=4.1.1.1 Properties (M)
- 4. `_pdf_enrichment/testcases/details/ETC-10.md` score=0.0194 title=ETC-10 Invalid Invoking ID - Get
- 5. `opal/4.2.3.2.txt` score=0.0164 title=4.2.3.2 Template (M)

### tc2.json (pass)
- target: Get C_PIN_MSID status=SUCCESS
- 1. `opal/4.2.1.8.txt` score=0.0308 title=4.2.1.8 C_PIN (M)
- 2. `opal/4.2.1.5.txt` score=0.0257 title=4.2.1.5 AccessControl (M)
- 3. `opal/4.3.1.6.txt` score=0.0252 title=4.3.1.6 AccessControl (M)
- 4. `opal/4.3.5.2.txt` score=0.0237 title=4.3.5.2 Locking (M)
- 5. `_pdf_enrichment/testcases/details/ETC-10.md` score=0.0230 title=ETC-10 Invalid Invoking ID - Get

### tc3.json (pass)
- target: StartSession SessionManager status=SUCCESS
- 1. `opal/4.2.1.8.txt` score=0.0274 title=4.2.1.8 C_PIN (M)
- 2. `opal/4.2.1.5.txt` score=0.0239 title=4.2.1.5 AccessControl (M)
- 3. `_pdf_enrichment/testcases/details/ETC-10.md` score=0.0219 title=ETC-10 Invalid Invoking ID - Get
- 4. `core/5.2.3.1.txt` score=0.0217 title=5.2.3.1 StartSession Method
- 5. `opal/4.2.1.6.txt` score=0.0164 title=4.2.1.6 ACE (M)

