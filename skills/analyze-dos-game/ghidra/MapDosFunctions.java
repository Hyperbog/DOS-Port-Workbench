// Map a DOS Port Workbench report to functions in the current analyzed program.
//@category DOS
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.MzLoader;
import ghidra.framework.Application;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;

public class MapDosFunctions extends GhidraScript {
    private final Gson json = new GsonBuilder().setPrettyPrinting().create();

    private static JsonObject readReport(Path input) throws IOException {
        byte[] bytes = Files.readAllBytes(input);
        boolean utf16 = bytes.length >= 2 &&
            ((bytes[0] == (byte) 0xff && bytes[1] == (byte) 0xfe) ||
             (bytes[0] == (byte) 0xfe && bytes[1] == (byte) 0xff));
        String text = new String(bytes, utf16 ? StandardCharsets.UTF_16 : StandardCharsets.UTF_8);
        return JsonParser.parseString(text.startsWith("\uFEFF") ? text.substring(1) : text).getAsJsonObject();
    }

    private FileBytes originalFile(String sha256) throws Exception {
        String recorded = currentProgram.getExecutableSHA256();
        if (recorded != null && !recorded.isEmpty() && !sha256.equalsIgnoreCase(recorded)) {
            throw new IllegalArgumentException("The report SHA-256 differs from the imported executable.");
        }
        FileBytes match = null;
        byte[] buf = new byte[65536];
        for (FileBytes file : currentProgram.getMemory().getAllFileBytes()) {
            if (file.getFileOffset() != 0) continue;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (long pos = 0; pos < file.getSize();) {
                monitor.checkCancelled();
                int size = (int) Math.min(buf.length, file.getSize() - pos);
                if (file.getOriginalBytes(pos, buf, 0, size) != size) throw new IOException("Short original file read");
                digest.update(buf, 0, size);
                pos += size;
            }
            if (sha256.equalsIgnoreCase(HexFormat.of().formatHex(digest.digest()))) {
                if (match != null) throw new IllegalArgumentException("Multiple imports match the report SHA-256.");
                match = file;
            }
        }
        if (match == null) throw new IllegalArgumentException("No original file bytes match the report SHA-256.");
        return match;
    }

    private void addFileOffset(JsonObject record, Address address, FileBytes source) {
        Memory memory = currentProgram.getMemory();
        AddressSourceInfo info = memory.getAddressSourceInfo(address);
        if (info != null && info.getFileOffset() >= 0 &&
            memory.locateAddressesForFileBytesOffset(source, info.getFileOffset()).contains(address)) {
            record.addProperty("file_offset", info.getFileOffset());
        }
    }

    private JsonObject describeFunction(Function function, FileBytes source) throws Exception {
        JsonObject record = new JsonObject();
        Address entry = function.getEntryPoint();
        record.addProperty("entry", entry.toString());
        record.addProperty("name", function.getName(true));
        addFileOffset(record, entry, source);
        JsonArray calls = new JsonArray();
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(entry)) {
            monitor.checkCancelled();
            if (!ref.getReferenceType().isCall()) continue;
            JsonObject call = new JsonObject();
            Address from = ref.getFromAddress();
            call.addProperty("from", from.toString());
            call.addProperty("type", ref.getReferenceType().getName());
            addFileOffset(call, from, source);
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(from);
            if (caller != null) call.addProperty("caller_entry", caller.getEntryPoint().toString());
            calls.add(call);
        }
        record.add("incoming_calls", calls);
        return record;
    }

    private String mapSite(JsonObject row, FileBytes file, long start, long end, int origin,
                           Map<String, JsonObject> functions) throws Exception {
        long offset = row.get("file_offset").getAsLong();
        byte[] expected = HexFormat.of().parseHex(row.get("bytes").getAsString().replace(" ", ""));
        String csip = row.get("cs_ip").getAsString();
        if (!csip.matches("[0-9a-fA-F]{4}:[0-9a-fA-F]{4}")) return "invalid_report_address";
        int segment = Integer.parseInt(csip.substring(0, 4), 16);
        int ip = Integer.parseInt(csip.substring(5), 16);
        long linear = (16L * segment + ip) & 0xfffff;
        if (offset != start + linear - origin || offset < start || expected.length == 0 ||
            expected.length > 15 || offset > end - expected.length) return "invalid_report_address";
        byte[] original = new byte[expected.length];
        if (file.getOriginalBytes(offset, original) != expected.length || !Arrays.equals(original, expected)) {
            return "report_bytes_differ";
        }
        List<Address> addresses = currentProgram.getMemory().locateAddressesForFileBytesOffset(file, offset)
            .stream().filter(a -> a.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace()))
            .distinct().toList();
        if (addresses.isEmpty()) return "unmapped_file_offset";
        if (addresses.size() > 1) {
            row.add("candidate_addresses", json.toJsonTree(addresses.stream().map(Address::toString).toList()));
            return "ambiguous_file_offset";
        }
        Address address = addresses.get(0);
        row.addProperty("ghidra_address", address.toString());
        Instruction instruction = currentProgram.getListing().getInstructionAt(address);
        if (instruction == null) return "no_instruction_at_site";
        row.addProperty("ghidra_instruction", instruction.toString());
        if (!Arrays.equals(instruction.getBytes(), expected)) return "instruction_bytes_differ";
        Function fn = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (fn == null) return "no_containing_function";
        String entry = fn.getEntryPoint().toString();
        row.addProperty("function_entry", entry);
        if (!functions.containsKey(entry)) functions.put(entry, describeFunction(fn, file));
        return "mapped";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 && (args.length != 0 || isRunningHeadless())) {
            throw new IllegalArgumentException("Pass the Workbench report path and a new output JSON path.");
        }
        Path input = args.length == 2 ? Path.of(args[0]) : askFile("Workbench report JSON", "Open").toPath();
        Path output = (args.length == 2 ? Path.of(args[1]) : askFile("New function map JSON", "Save").toPath()).toAbsolutePath();
        if (Files.exists(output)) throw new IOException("Choose a new output file: " + output);
        JsonObject report = readReport(input);
        if (currentProgram == null || !"x86:LE:16:Real Mode".equals(currentProgram.getLanguageID().toString())) {
            throw new IllegalArgumentException("Open the matching x86 16-bit real-mode program.");
        }
        JsonObject exe = report.getAsJsonObject("executable");
        if (report.get("report_version").getAsInt() != 1 || exe == null || !exe.has("trace")) {
            throw new IllegalArgumentException("Expected a Workbench v1 report with decoded trace findings.");
        }
        String format = exe.get("format").getAsString();
        boolean com = format.startsWith("DOS COM");
        if (!(com || ("DOS MZ".equals(format) && MzLoader.MZ_NAME.equals(currentProgram.getExecutableFormat())))) {
            throw new IllegalArgumentException("Use the original COM image or Ghidra's old-style DOS MZ loader.");
        }
        String sha = exe.get("sha256").getAsString();
        FileBytes file = originalFile(sha);
        JsonArray resident = exe.getAsJsonObject("regions").getAsJsonArray("resident_image");
        long start = resident.get(0).getAsLong(), end = resident.get(1).getAsLong();
        if (start < 0 || start >= end || end > file.getSize()) throw new IllegalArgumentException("Invalid resident image limits.");
        Map<String, Integer> counts = new TreeMap<>();
        Map<String, JsonObject> functions = new TreeMap<>();
        JsonArray sites = new JsonArray();
        for (JsonElement item : exe.getAsJsonObject("trace").getAsJsonArray("findings")) {
            monitor.checkCancelled();
            JsonObject row = item.getAsJsonObject().deepCopy();
            String status = mapSite(row, file, start, end, com ? 0x100 : 0, functions);
            row.addProperty("map_status", status);
            counts.merge(status, 1, Integer::sum);
            sites.add(row);
        }
        JsonObject result = new JsonObject();
        result.addProperty("map_version", 1);
        result.addProperty("ghidra_version", Application.getApplicationVersion());
        result.add("executable", report.get("entry"));
        result.addProperty("sha256", sha);
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("loader", currentProgram.getExecutableFormat());
        result.add("status_counts", json.toJsonTree(counts));
        result.add("functions", json.toJsonTree(functions));
        result.add("sites", sites);
        Path temporary = Files.createTempFile(output.getParent(), ".dos-function-map-", ".tmp");
        try {
            Files.writeString(temporary, json.toJson(result) + System.lineSeparator(), StandardCharsets.UTF_8);
            monitor.checkCancelled();
            Files.move(temporary, output);
        } finally {
            Files.deleteIfExists(temporary);
        }
        println("Mapped " + counts.getOrDefault("mapped", 0) + "/" + sites.size() +
                " findings to " + functions.size() + " functions. " + output);
    }
}
