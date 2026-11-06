// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Revision 2 fixed import-only bridge; named captured bytes repair dynamic-library ELF imports. No target execution, analysis, project save or caller script.
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SourceType;

class HeptaGhidraInventoryV2 {
    static String bounded(String text,int limit) {
        if(text.length()<=limit)return text;
        int end=limit;
        if(end>0 && Character.isHighSurrogate(text.charAt(end-1)))end--;
        return text.substring(0,end);
    }
    static String digest(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
    }
    static String json(Object value) {
        if(value==null)return "null";
        if(value instanceof Boolean || value instanceof Number)return value.toString();
        if(value instanceof String text) {
            StringBuilder out=new StringBuilder("\"");
            for(int i=0;i<text.length();i++) {
                char c=text.charAt(i);
                if(c=='"' || c=='\\')out.append('\\').append(c);
                else if(c<32 || Character.isSurrogate(c))out.append(String.format("\\u%04x",(int)c));
                else out.append(c);
            }
            return out.append('"').toString();
        }
        if(value instanceof Map<?,?> map) {
            List<String> parts=new ArrayList<>();
            for(var entry:map.entrySet())parts.add(json(entry.getKey().toString())+":"+json(entry.getValue()));
            return "{"+String.join(",",parts)+"}";
        }
        if(value instanceof List<?> list) {
            List<String> parts=new ArrayList<>();
            for(Object item:list)parts.add(json(item));
            return "["+String.join(",",parts)+"]";
        }
        throw new IllegalArgumentException("unsupported JSON observation");
    }
    public static void main(String[] input) throws Exception {
        if(input.length!=3)throw new IllegalArgumentException("fixed installation, captured ELF and response budget required");
        int budget=Integer.parseInt(input[2]);
        if(budget<1024 || budget>65536)throw new IllegalArgumentException("invalid response budget");
        byte[] bytes=Files.readAllBytes(Path.of(input[1]));
        if(bytes.length<4 || bytes.length>8*1024*1024 || bytes[0]!=0x7f || bytes[1]!='E' || bytes[2]!='L' || bytes[3]!='F')
            throw new IllegalArgumentException("bounded captured ELF required");
        PrintStream result=System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        var config=new HeadlessGhidraApplicationConfiguration();
        config.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(new File(input[0])),config);
        if(!Application.getApplicationVersion().equals("12.2"))throw new IllegalStateException("unexpected Ghidra version");
        var loader=ProgramLoader.builder().source(new ByteArrayProvider("hepta-owned-input",bytes)).name("hepta-owned-input")
            .loaders(ElfLoader.class)
            .addLoaderArg("-loader-loadLibraries","false")
            .addLoaderArg("-loader-linkExistingProjectLibraries","false");
        try(var loaded=loader.load()) {
            Program program=loaded.getPrimary().getDomainObject();
            List<Map<String,Object>> blocks=new ArrayList<>();
            MemoryBlock[] allBlocks=program.getMemory().getBlocks();
            for(int i=0;i<Math.min(allBlocks.length,128);i++) {
                MemoryBlock block=allBlocks[i];
                String name=block.getName();
                Map<String,Object> row=new LinkedHashMap<>();
                row.put("name",bounded(name,256));
                row.put("name_complete",name.length()<=256);
                row.put("name_sha256",digest(name));
                row.put("start_address",block.getStart().toString());
                row.put("end_address",block.getEnd().toString());
                row.put("size_bytes",Long.toUnsignedString(block.getSize()));
                row.put("read",block.isRead());
                row.put("write",block.isWrite());
                row.put("execute",block.isExecute());
                row.put("initialized",block.isInitialized());
                blocks.add(row);
            }
            List<Map<String,Object>> symbols=new ArrayList<>();
            SymbolIterator iterator=program.getSymbolTable().getAllSymbols(false);
            int scanned=0, imported=0;
            while(scanned<4096 && iterator.hasNext()) {
                Symbol symbol=iterator.next();
                scanned++;
                if(symbol.getSource()!=SourceType.IMPORTED)continue;
                imported++;
                if(symbols.size()>=128)continue;
                String name=symbol.getName(true);
                Map<String,Object> row=new LinkedHashMap<>();
                row.put("qualified_name",bounded(name,256));
                row.put("name_complete",name.length()<=256);
                row.put("name_sha256",digest(name));
                row.put("address",symbol.getAddress().toString());
                row.put("symbol_type",symbol.getSymbolType().toString());
                row.put("source_type",symbol.getSource().toString());
                symbols.add(row);
            }
            boolean scanComplete=!iterator.hasNext();
            Map<String,Object> report=new LinkedHashMap<>();
            report.put("schema","hepta.rea.ghidra-observation.v2");
            report.put("bridge_revision",2);
            report.put("source_sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
            report.put("source_bytes",bytes.length);
            report.put("engine_version",Application.getApplicationVersion());
            report.put("operation","inventory");
            report.put("loader","ghidra.app.util.opinion.ElfLoader");
            report.put("format",program.getExecutableFormat());
            report.put("language_id",program.getLanguageID().toString());
            report.put("compiler_spec_id",program.getCompilerSpec().getCompilerSpecID().toString());
            report.put("image_base",program.getImageBase().toString());
            report.put("memory_block_count",allBlocks.length);
            report.put("memory_blocks",blocks);
            report.put("symbol_table_count",program.getSymbolTable().getNumSymbols());
            report.put("scanned_symbols",scanned);
            report.put("symbol_scan_complete",scanComplete);
            report.put("observed_imported_symbols_in_scan",imported);
            report.put("imported_symbols",symbols);
            report.put("target_executed",false);
            report.put("auto_analysis_performed",false);
            report.put("decompilation_performed",false);
            report.put("external_libraries_loaded",false);
            report.put("project_saved",false);
            report.put("coverage","partial");
            String encoded;
            while(true) {
                report.put("returned_memory_blocks",blocks.size());
                report.put("omitted_memory_blocks",allBlocks.length-blocks.size());
                report.put("returned_imported_symbols",symbols.size());
                report.put("omitted_imported_symbols_in_scan",imported-symbols.size());
                encoded=json(report);
                if(encoded.getBytes(StandardCharsets.UTF_8).length+1<=budget)break;
                if(blocks.isEmpty() && symbols.isEmpty())throw new IllegalStateException("inventory summary exceeds response budget");
                if(symbols.size()>=blocks.size())symbols.subList(symbols.size()/2,symbols.size()).clear();
                else blocks.subList(blocks.size()/2,blocks.size()).clear();
            }
            result.println(encoded);
        }
    }
}
