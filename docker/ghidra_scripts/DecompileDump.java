// Headless GhidraScript: decompile one function (scriptArg) or all, emit JSON
// between DECOMP_JSON_START/END markers. Java (not .py) so no PyGhidra needed.
// @category CTF
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;

public class DecompileDump extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String target = a.length > 0 ? a[0] : null;
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Function f : fm.getFunctions(true)) {
            if (target != null && !f.getName().equals(target)) continue;
            DecompileResults r = dec.decompileFunction(f, 60, monitor);
            String c = (r != null && r.decompileCompleted())
                ? r.getDecompiledFunction().getC() : null;
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"name\":").append(js(f.getName()))
              .append(",\"entry\":").append(js(f.getEntryPoint().toString()))
              .append(",\"c\":").append(c == null ? "null" : js(c)).append("}");
        }
        sb.append("]");
        println("DECOMP_JSON_START");
        println(sb.toString());
        println("DECOMP_JSON_END");
    }
    static String js(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            if (ch == '"') b.append("\\\"");
            else if (ch == '\\') b.append("\\\\");
            else if (ch == '\n') b.append("\\n");
            else if (ch == '\r') b.append("\\r");
            else if (ch == '\t') b.append("\\t");
            else if (ch < 0x20) b.append(String.format("\\u%04x", (int) ch));
            else b.append(ch);
        }
        return b.append("\"").toString();
    }
}
