fn main() {
    let swift_re = regex::Regex::new(r"(?m)^([^:\s][^:\n]*):(\d+):\d+:\s*error:\s*([^\n]*)").unwrap();
    let go_compile_re = regex::Regex::new(r"(?m)^([^:\s][^:\n]*\.go):(\d+):\d+:\s*([^\n]*)").unwrap();
    let go_with = "./main.go:8:7: error: cannot find package";
    let go_without = "./main.go:8:7: undefined: foo";
    println!("swift on go-with-error: {:?}", swift_re.captures(go_with).map(|c| (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str())));
    println!("swift on go-without:    {:?}", swift_re.captures(go_without).map(|c| (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str())));
    println!("go_compile on with-error: {:?}", go_compile_re.captures(go_with).map(|c| (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str())));

    let python_re = regex::Regex::new(r#"(?ms)Traceback \(most recent call last\):.*?File "([^"]+)", line (\d+).*?^(\w+(?:Error|Exception|Warning)):\s*([^\n]*)"#).unwrap();
    let mut deep = String::from("Traceback (most recent call last):\n");
    for i in 1..40 { deep.push_str(&format!("  File \"f{}.py\", line {}, in func{}\n", i, i, i)); }
    deep.push_str("TypeError: bad\n");
    let lines: Vec<&str> = deep.lines().collect();
    let tail: String = lines[lines.len().saturating_sub(30)..].join("\n");
    println!("\ndeep traceback total lines: {}", lines.len());
    println!("tail starts with 'Traceback': {}", tail.starts_with("Traceback"));
    println!("python_re on full:  {:?}", python_re.captures(&deep).map(|c| (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str(), c.get(3).unwrap().as_str())));
    println!("python_re on tail:  {:?}", python_re.captures(&tail).map(|c| (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str(), c.get(3).unwrap().as_str())));

    let node_re = regex::Regex::new(r"Error:\s*(.*)\n\s+at\s+.*\(([^()]+):(\d+):\d+\)").unwrap();
    let node_multi = "Error: Cannot find module 'foo'\n    at require (app.js:10:15)\n    at Object.<anonymous> (app.js:3:1)";
    println!("\nnode multi-frame: {:?}", node_re.captures(node_multi).map(|c| (c.get(2).unwrap().as_str(), c.get(3).unwrap().as_str())));

    let bun_re = regex::Regex::new(r"error:\s*(.*)\n\s+at\s+([^()]+):(\d+):\d+").unwrap();
    let benign = "ValueError: error: invalid\n    at line 5:18";
    println!("bun on benign: {:?}", bun_re.captures(benign).map(|c| (c.get(2).unwrap().as_str(), c.get(3).unwrap().as_str())));

    // Go compile with .ts file (matches go_compile? no, requires .go)
    let ts_re = regex::Regex::new(r#"(?M)^([^:\s][^:\n]*?)\((\d+),\d+\):\s+error\s+(TS\d+):\s*([^\n]*)"#).unwrap();
    let py_with_paren = "Traceback (most recent call last):\n  File \"app.py\", line 5, in <module>\n    foo()\nTypeError: bad";
    println!("\nts_re on python (false pos?): {:?}", ts_re.captures(py_with_paren).map(|c| c.get(0).unwrap().as_str()));
}
