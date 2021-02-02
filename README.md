The base64 custom search command is a command for base64 encoding and decoding. Includes a command for base64 encoded content in MIME encoded data.

This major revision maintains compatibility with previous commands. Fixes are listed in the version notes.

### base64 command

```
... | base64 field=your_field [action=(encode|decode)] [mode=(replace|append)] [backslash_escape=(True|False)] [encoding="charset_name"] [suppress_error=(True|False)] [alphabet="custom_alphabet"]
```

* field : field to encode or decode.
* action : encode (default) or decode the content. Optional.
* mode : replace the existing field content (default) or create a new field named base64 (mode append). Optional.
* backslash_escape : escape non-ASCII and non-printable content (default). Optional.
* encoding : decode output with specified encoding, falls back to backslash_escape if charset is not found. Optional.
* suppress_error : do not raise errors if set to True. Optional, default to False.
* alphabet : string (not field) for alternate base64 alphabet. Optional.

**Note on decoding:**

While the input string can be anything for the encoding operation, it should respect the alphabet `[a-zA-Z0-9/=]` if a custom alphabet is not used. If the input string length is incorrect, the last returned character may be incorrect. If other format requirements are not respected, the command may throw errors (except if you set the flag `suppress_error`).

In the following example, we assume we are working on proxy/web logs and those will contain a field uri. This field will contains URI links and some of them will contains
an argument plop which refers to base64 encoded data.

So, to get it working:

* find the plop command
* extract the base64 content (command rex)
* decode the base64 content

Here is one way of doing it in Splunk:

... your search to get field 'uri' for example...
```
"plop=*"
| rex field=uri "plop=(?<content_to_decode>[a-zA-Z0-9/=]*)"
| base64 field="content_to_decode" action="decode" mode="append"
```

### mimedecode command

```
... | mimedecode field=your_field [mode=(replace|append)] [suppress_error=(True|False)]
```

* field : field to decode.
* mode : replace the existing field content (default) or create a new field named base64 (mode append). Optional.
* suppress_error : do not raise errors if set to True. Optional, default to False.

A simple example to decode likely encoded header field, with a very naive error check:
```
mime_header="=?*"
| eval mime_header = if(match(mime_header, "\?=$"), mime_header, mime_header . "?=") 
| mimedecode field="mime_header" mode="append"
```

**Note on decoding:**

No special error handling outside is provided for partial data. If partial data needs to be decoded, correct the data with an `eval` or `rex mode=sed` command before executing the command.


### Lookup versions

Both commands can be executed as external lookups with fewer options.

```
| lookup base64 encoded AS your_field OUTPUT decoded AS your_decoded_field
```

```
| lookup mimedecode encoded AS your_field OUTPUT decoded AS your_decoded_field
```

#### Support

This is an open source project, no support provided, public repository available.

https://github.com/malvidin/base64

*The modified splunklib will be removed when the related issue with leading spaces is resolved.*

### History

**v2.0.1**
- Cleaner output
- Better option validation
- Escape null bytes from results

**v2.0**
- Avoid errors by adding padding
- Less ambiguous escaped output
- Optional charset when decoding
- Lookups with default options
- Return original event if input field does not exist
- MIME decoding for base64 encoded MIME
- Workaround for leading spaces

**v1.1**
- non printable characters are presented as hexadecimal when decoding (ex: `base64=<%PDF\x00\x00`).

**v1.0**
- Initial release
