# Ghost Data Still Exists solution

Install the Python dependencies from the repository root:

```powershell
python -m pip install -r code/requirements.txt
python -m unittest discover -s code -p "test_*.py" -v
python code/main.py
```

`main.py` first checks the 32 public sample cases and validates their step schema and evidence references. It does not start the 518-request run or write the root `output.csv` if sample answers or contract checks fail. The implementation uses deterministic Python rules; OCR extracts text from the participant-provided screenshots and preserves their manifest evidence IDs.
