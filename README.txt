Machina CAD De-ID pipeline
==========================

Run (Python 3.10+, Linux, case-sensitive filesystem):

  pip install -r code/requirements.txt
  bash get-input.sh                                   # raw corpus into ./input
  python3 code/run.py discover  --input ./input --state ./state
  python3 code/run.py transform --input ./input --state ./state --output ./cleaned-corpus
  python3 code/run.py verify    --state ./state --output ./cleaned-corpus

./state holds the private HMAC key, the identifier registry and run logs. It is
not part of the submission. Re-running with the same key reproduces the output.
transform is resumable (existing outputs are skipped; --force to redo).

Method
------
1. discover: reads identity fields from every file, including inside archives
   and native containers: STEP FILE_NAME author/organization and PERSON /
   ORGANIZATION entities, IGES global author/organization, DXF $LASTSAVEDBY,
   XML-style properties (SOLIDWORKS docProps, FreeCAD Document.xml, 3MF and
   SVG metadata), OLE summary properties, PDF metadata, Windows/Unix user
   profile paths (ASCII and UTF-16), and repository owner/project names in
   corpus paths.
2. transform: replaces every registry term, e-mail address, non-standard URL
   host and user-profile name. Each word maps to a pseudonym of the same
   length and character classes via HMAC, so one identity always gets the same
   pseudonym, different identities stay distinct, and identity fields stay
   filled. Because lengths never change, binary formats, fixed-column formats
   and file references stay valid; a renamed file and every reference to it
   change identically.
   Containers are opened and rebuilt: zip (and zip-based CAD such as FCStd,
   3MF, F3D), 7z, tar, gz/bz2/xz, PDF (metadata, XMP, page text, links,
   bookmarks, attachments), and the SOLIDWORKS 2015+ container (every stream
   is inflated, cleaned, deflated; sizes, CRCs and directory offsets fixed and
   self-checked). Geometry, units, tolerances, configurations and BOM data are
   never re-serialised.
3. verify: re-opens every output file and container and counts registry terms
   that remain.

Limitations and exceptions
--------------------------
(Filled in per attempt from state/report-*.json, using final paths only.)
- Text inside raster images, logos and embedded previews is not yet detected.
- Private directory names in saved paths other than the user-profile name are
  left unchanged.
- OLE-based native files (older SOLIDWORKS, Inventor) and other binary native
  formats are cleaned with the length-preserving binary pass only; internally
  compressed streams in those formats are not inflated.
- rar and unix-compress archives are passed through the binary pass and not
  rebuilt.
- Files that are empty or structurally invalid in the source are kept at their
  mapped path, cleaned with the binary pass where possible.
