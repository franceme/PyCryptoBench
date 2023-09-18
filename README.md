# PyCryptoBench

A purposely vulnerable cryptographic dataset to help advanced code analysis tools.

Feel free to download this sqlite or use it live at [DBHub](https://dbhub.io/frantzme/PyCryptoBench.sqlite).

# To loop through this database within Python

```python
import mystring #https://pypi.org/project/mystring/
from ephfile import ephfile #https://pypi.org/project/ephfile

api_key = <<APIKEY>> #API Key for DBHub.io

testfiles = mystring.frame.from_dbhub_query("Select * From main;", api_key, "frantzme", "PyCryptoBench.sqlite")

for testfile in testfiles.roll:
  """
  # Content

  testfile = {
    'FileName': [str]
    'FileDir': [str]
    'Rule': [int]
    'HasPattern':[bool]
    'TestType':[str|None]
    'FieldSensitive':[bool]
    'Global':[bool]
    'InterProcedural':[bool]
    'DBLInterprocedural':[bool]
    'PathSensitive':[bool]
    'FieldSensitive_INT':[int]
    'Global_INT':[int]
    'InterProcedural_INT':[int]
    'DBLInterprocedural_INT':[int]
    'PathSensitive_INT':[int]
    'Imports':[str]
    'Contents':"b64:"+[str]
    'HasVuln':[bool]
    'File Qual Name':[str|None]
    'Program Lines':[int]
    'Total Lines':[int]
    'CC Complexity':[int|None]
    'MCC':[int]
  }
  """
  testcontent = mystring.string.frombase64(testfile['Contents'].replace('b64:',''))
  with ephfile("testfile.py", testcontent) as eph:
    #eph = temporary file written at testfile.py, with the test content already written in
    #eph() = filepath
```

You simply have to install mystring and ephfile using the following command: `python3 -m pip install --upgrade mystring ephfile`.

## Reference

If you find this database useful, please cite our NDSS'22 [Poster](https://www.ndss-symposium.org/wp-content/uploads/NDSS2022Poster_paper_28.pdf).
```tex
@inproceedings{frantz2022poster,
  title={POSTER: Precise Detection of Unprecedented Python Cryptographic Misuses Using On-Demand Analysis},
  author={Frantz, Miles and Xiao, Ya and Pias, Tanmoy Sarkar and Yao, Danfeng Daphne},
  booktitle={The Network and Distributed System Security (NDSS) Symposium},
  year={2022}
}
```