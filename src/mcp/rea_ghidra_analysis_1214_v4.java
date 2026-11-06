// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Revision 4, pinned Ghidra 12.1.4 ELF analysis over admitted bytes. No target execution or caller script.
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TimeoutTaskMonitor;

class HeptaGhidraAnalysis1214V4 {
    static final List<String> ANALYZERS=List.of(
        "ASCII Strings",
        "Apply Data Archives",
        "Call Convention ID",
        "Call-Fixup Installer",
        "Create Address Tables",
        "DWARF",
        "Data Reference",
        "Decompiler Switch Analysis",
        "Demangler GNU",
        "Disassemble Entry Points",
        "ELF Scalar Operand References",
        "Embedded Media",
        "External Entry References",
        "Function ID",
        "Function Start Pre Search",
        "Function Start Search",
        "Function Start Search After Code",
        "Function Start Search After Data",
        "GCC Exception Handlers",
        "Non-Returning Functions - Discovered",
        "Non-Returning Functions - Known",
        "Reference",
        "Shared Return Calls",
        "Stack",
        "Subroutine References",
        "x86 Constant Reference Analyzer");
    static final List<String> DISABLED_ANALYZERS=List.of(
        "Aggressive Instruction Finder",
        "Condense Filler Bytes",
        "Decompiler Parameter ID",
        "Variadic Function Signature Override");
    static final String OPTIONS_SHA256="a5531d741cf6e4e42215ea1f4268049600b80c3a03ab7d3586bd3a7bbb7acd75";
    static final String OPTIONS_FORMAT="hepta.ghidra.analysis-options.key-type-class-value.v1";
    static final int SCAN_LIMIT=4096,ROW_LIMIT=128,BODY_RANGE_LIMIT=128,ANALYSIS_SECONDS=30,DECOMPILE_SECONDS=15;

    static String bounded(String text,int limit) {
        if(text.length()<=limit)return text;
        int end=limit;
        if(end>0 && Character.isHighSurrogate(text.charAt(end-1)))end--;
        return text.substring(0,end);
    }
    static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    static String digest(String text) throws Exception {
        return digest(text.getBytes(StandardCharsets.UTF_8));
    }
    static String address(Address value) {
        if(value.isExternalAddress())return "EXTERNAL:0x"+Long.toUnsignedString(value.getOffset(),16);
        return value.isMemoryAddress()
            ? "0x"+Long.toUnsignedString(value.getOffset(),16) : value.toString(true);
    }
    static boolean validAddress(String value) {
        return value.matches("0x(?:0|[1-9a-f][0-9a-f]{0,15})");
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

    static Map<String,Object> functionRow(Function function) throws Exception {
        Map<String,Object> row=new LinkedHashMap<>();
        String name=function.getName(true);
        String signature=function.getPrototypeString(false,false);
        row.put("entry_address",address(function.getEntryPoint()));
        row.put("name",bounded(name,256));
        row.put("name_complete",name.length()<=256);
        row.put("name_sha256",digest(name));
        row.put("signature",bounded(signature,1024));
        row.put("signature_complete",signature.length()<=1024);
        row.put("signature_sha256",digest(signature));
        row.put("external",function.isExternal());
        row.put("thunk",function.isThunk());
        row.put("body_min_address",address(function.getBody().getMinAddress()));
        row.put("body_max_address",address(function.getBody().getMaxAddress()));
        row.put("body_address_count",Long.toUnsignedString(function.getBody().getNumAddresses()));
        return row;
    }

    static Map<String,Object> externalFunctionRow(Function function) throws Exception {
        if(!function.isExternal() || !function.getEntryPoint().isExternalAddress())
            throw new IllegalStateException("external function has no explicit external address");
        Map<String,Object> row=new LinkedHashMap<>();
        String name=function.getName(true),signature=function.getPrototypeString(false,false);
        row.put("entry_address",address(function.getEntryPoint()));
        row.put("name",bounded(name,256));
        row.put("name_complete",name.length()<=256);
        row.put("name_sha256",digest(name));
        row.put("signature",bounded(signature,1024));
        row.put("signature_complete",signature.length()<=1024);
        row.put("signature_sha256",digest(signature));
        row.put("external",true);
        row.put("thunk",function.isThunk());
        return row;
    }

    static void selectedBody(Function function,Map<String,Object> row) {
        var space=function.getEntryPoint().getAddressSpace();
        var iterator=function.getBody().getAddressRanges(true);
        List<Map<String,Object>> ranges=new ArrayList<>();
        while(iterator.hasNext()) {
            if(ranges.size()==BODY_RANGE_LIMIT)
                throw new IllegalStateException("selected function body exceeds the fixed complete-range budget");
            var range=iterator.next();
            if(!space.equals(range.getMinAddress().getAddressSpace()) ||
                    !space.equals(range.getMaxAddress().getAddressSpace()) ||
                    !range.getMinAddress().isMemoryAddress() || range.getMinAddress().isExternalAddress())
                throw new IllegalStateException("selected body has an unsupported address space");
            Map<String,Object> item=new LinkedHashMap<>();
            item.put("min_address",address(range.getMinAddress()));
            item.put("max_address",address(range.getMaxAddress()));
            ranges.add(item);
        }
        if(ranges.isEmpty())throw new IllegalStateException("selected internal function body is empty");
        row.put("body_ranges",ranges);
        row.put("body_range_count",ranges.size());
        row.put("body_ranges_complete",true);
    }

    static Map<String,Object> referenceRow(Reference reference) {
        Map<String,Object> row=new LinkedHashMap<>();
        row.put("from_address",address(reference.getFromAddress()));
        row.put("to_address",address(reference.getToAddress()));
        row.put("from_space",reference.getFromAddress().getAddressSpace().getName());
        row.put("to_space",reference.getToAddress().getAddressSpace().getName());
        row.put("reference_type",reference.getReferenceType().toString());
        row.put("source_type",reference.getSource().toString());
        row.put("operand_index",reference.getOperandIndex());
        row.put("call",reference.getReferenceType().isCall());
        row.put("primary",reference.isPrimary());
        return row;
    }


    static List<Map<String,Object>> optionSnapshot(Options options) {
        List<String> names=new ArrayList<>(options.getOptionNames());
        Collections.sort(names);
        List<Map<String,Object>> snapshot=new ArrayList<>();
        for(String name:names) {
            Object value=options.getObject(name,null);
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("name",name);
            row.put("type",options.getType(name).toString());
            row.put("value_class",value==null?null:value.getClass().getName());
            if(value==null || value instanceof String || value instanceof Boolean ||
                    value instanceof Integer || value instanceof Long ||
                    value instanceof Double || value instanceof Float)
                row.put("value",value);
            else if(value instanceof byte[] bytes)row.put("value",HexFormat.of().formatHex(bytes));
            else if(value instanceof Enum<?> choice)row.put("value",choice.name());
            else row.put("value",value.toString());
            snapshot.add(row);
        }
        return snapshot;
    }


    static void analyze(Program program,Map<String,Object> report) throws Exception {
        if(!program.getLanguageID().toString().equals("x86:LE:64:default") ||
                !program.getCompilerSpec().getCompilerSpecID().toString().equals("gcc"))
            throw new IllegalArgumentException("fixed default profile requires x86:LE:64:default/gcc");
        AutoAnalysisManager manager=AutoAnalysisManager.getAnalysisManager(program);
        TimeoutTaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(ANALYSIS_SECONDS,TimeUnit.SECONDS);
        int transaction=program.startTransaction("Fixed Ghidra 12.1.4 x86_64 default analysis");
        boolean commit=false;
        try {
            Options options=program.getOptions(Program.ANALYSIS_PROPERTIES);
            manager.initializeOptions();
            var snapshot=optionSnapshot(options);
            if(snapshot.size()!=146 || !digest(json(snapshot)).equals(OPTIONS_SHA256))
                throw new IllegalStateException("fixed default analysis option snapshot is unavailable");
            List<String> disabled=new ArrayList<>(),enabled=new ArrayList<>();
            for(String name:options.getOptionNames()) {
                if(manager.getAnalyzer(name)==null)continue;
                (options.getBoolean(name,false)?enabled:disabled).add(name);
            }
            Collections.sort(enabled);
            Collections.sort(disabled);
            if(!enabled.equals(ANALYZERS) || !disabled.equals(DISABLED_ANALYZERS))
                throw new IllegalStateException("fixed default analyzer enablement is unavailable");
            // Preserve observed defaults, including the two analyzer Max Threads values of 2.
            // Caller options and the original npm NoReturnFix post-script are not applied.
            manager.reAnalyzeAll(null);
            manager.startAnalysis(monitor,false);
            monitor.checkCancelled();
            if(!digest(json(optionSnapshot(options))).equals(OPTIONS_SHA256))
                throw new IllegalStateException("fixed default analysis options changed during analysis");
            String log=manager.getMessageLog().toString();
            report.put("enabled_analyzers",enabled);
            report.put("disabled_analyzers",disabled);
            report.put("disabled_analyzer_count",disabled.size());
            report.put("disabled_analyzers_sha256",digest(json(disabled)));
            report.put("analysis_options_format",OPTIONS_FORMAT);
            report.put("analysis_option_count",snapshot.size());
            report.put("analysis_options_sha256",OPTIONS_SHA256);
            report.put("analysis_options_unchanged",true);
            report.put("no_return_repair_applied",false);
            report.put("analysis_log",bounded(log,2048));
            report.put("analysis_log_complete",log.length()<=2048);
            report.put("analysis_log_sha256",digest(log));
            report.put("analysis_completed",true);
            report.put("analysis_timeout_seconds",ANALYSIS_SECONDS);
            report.put("instruction_count_after_analysis",program.getListing().getNumInstructions());
            report.put("reported_function_count_after_analysis",program.getFunctionManager().getFunctionCount());
            commit=true;
        } finally {
            monitor.cancel();
            manager.dispose();
            program.endTransaction(transaction,commit);
        }
    }

    static void functions(Program program,Map<String,Object> report) throws Exception {
        FunctionIterator iterator=program.getFunctionManager().getFunctions(true);
        List<Map<String,Object>> rows=new ArrayList<>();
        int scanned=0;
        while(iterator.hasNext() && scanned<SCAN_LIMIT) {
            Function function=iterator.next();
            if(function.isExternal())continue;
            scanned++;
            if(rows.size()<ROW_LIMIT)rows.add(functionRow(function));
        }
        report.put("functions",rows);
        report.put("scanned_functions",scanned);
        report.put("returned_functions",rows.size());
        report.put("omitted_functions_in_scan",scanned-rows.size());
        report.put("function_scan_complete",!iterator.hasNext());
        FunctionIterator external=program.getFunctionManager().getExternalFunctions();
        List<Map<String,Object>> externalRows=new ArrayList<>();
        int externalScanned=0;
        while(external.hasNext() && externalScanned<SCAN_LIMIT) {
            Function function=external.next();
            externalScanned++;
            if(externalRows.size()<ROW_LIMIT)externalRows.add(externalFunctionRow(function));
        }
        report.put("function_inventory_scope","internal_and_external_separate");
        report.put("external_functions",externalRows);
        report.put("scanned_external_functions",externalScanned);
        report.put("returned_external_functions",externalRows.size());
        report.put("omitted_external_functions_in_scan",externalScanned-externalRows.size());
        report.put("external_function_scan_complete",!external.hasNext());
    }

    static void xrefs(Program program,Function function,Map<String,Object> report) {
        List<Map<String,Object>> incoming=new ArrayList<>(),outgoing=new ArrayList<>();
        ReferenceIterator incomingIterator=program.getReferenceManager().getReferencesTo(function.getEntryPoint());
        int scannedIn=0,scannedOut=0;
        while(incomingIterator.hasNext() && scannedIn<SCAN_LIMIT) {
            Reference reference=incomingIterator.next();
            scannedIn++;
            if(incoming.size()<ROW_LIMIT)incoming.add(referenceRow(reference));
        }
        boolean incomingComplete=!incomingIterator.hasNext(),outgoingComplete=true;
        AddressIterator sources=program.getReferenceManager().getReferenceSourceIterator(function.getBody(),true);
        outer: while(sources.hasNext()) {
            Address source=sources.next();
            for(Reference reference:program.getReferenceManager().getReferencesFrom(source)) {
                if(scannedOut==SCAN_LIMIT) { outgoingComplete=false;break outer; }
                scannedOut++;
                if(outgoing.size()<ROW_LIMIT)outgoing.add(referenceRow(reference));
            }
        }
        report.put("incoming_scope","exact_function_entry");
        report.put("outgoing_scope","selected_function_body");
        report.put("incoming_references",incoming);
        report.put("outgoing_references",outgoing);
        report.put("scanned_incoming_references",scannedIn);
        report.put("scanned_outgoing_references",scannedOut);
        report.put("returned_incoming_references",incoming.size());
        report.put("returned_outgoing_references",outgoing.size());
        report.put("omitted_incoming_references_in_scan",scannedIn-incoming.size());
        report.put("omitted_outgoing_references_in_scan",scannedOut-outgoing.size());
        report.put("incoming_scan_complete",incomingComplete);
        report.put("outgoing_scan_complete",outgoingComplete);
    }


    static final class OwnedChild {
        final ProcessHandle handle;
        final long pid,startTicks,parentPid;
        final String started,command,key,firstObservedPhase;
        final int depth;
        boolean explicitDecompilerCandidate,termSent,killSent;
        String beforeCleanup="unobserved",finalState="unobserved",failure=null;
        OwnedChild(ProcessHandle handle,long[] stat,String phase) throws Exception {
            this.handle=handle;
            pid=handle.pid();
            startTicks=stat[2];
            parentPid=stat[1];
            started=handle.info().startInstant().orElseThrow(
                ()->new IllegalStateException("native child start identity unavailable")).toString();
            command=handle.info().command().orElse("<unavailable>");
            key=pid+":"+startTicks;
            firstObservedPhase=phase;
            int levels=0;
            ProcessHandle cursor=handle;
            while(levels<64) {
                var parent=cursor.parent();
                if(parent.isEmpty())break;
                cursor=parent.get();
                levels++;
                if(cursor.pid()==ProcessHandle.current().pid())break;
            }
            depth=levels;
        }
        boolean isDecompiler() {
            return Path.of(command).getFileName().toString().equals("decompile");
        }
        Map<String,Object> observation() {
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("pid",pid);
            row.put("start_instant",started);
            row.put("start_ticks",Long.toString(startTicks));
            row.put("parent_pid",parentPid);
            row.put("command",bounded(command,1024));
            row.put("first_observed_phase",firstObservedPhase);
            row.put("role_attribution","phase_and_executable_inference");
            row.put("role",explicitDecompilerCandidate?"explicit_decompiler_candidate":
                isDecompiler()?"auto_analysis_decompiler_candidate":"other_engine_helper");
            row.put("explicit_decompiler_candidate",explicitDecompilerCandidate);
            row.put("state_before_cleanup",beforeCleanup);
            row.put("term_sent",termSent);
            row.put("kill_sent",killSent);
            row.put("final_state",finalState);
            row.put("exit_confirmed",finalState.equals("absent") || finalState.equals("identity_changed"));
            row.put("failure",failure);
            return row;
        }
    }

    static long[] procStat(long pid) throws Exception {
        String text=Files.readString(Path.of("/proc",Long.toString(pid),"stat"),StandardCharsets.US_ASCII);
        int end=text.lastIndexOf(')');
        if(end<0 || !text.substring(0,text.indexOf(' ')).equals(Long.toString(pid)))
            throw new IllegalStateException("native child proc identity is malformed");
        String[] fields=text.substring(end+2).trim().split(" +");
        if(fields.length<20 || fields[0].length()!=1)
            throw new IllegalStateException("native child proc state is incomplete");
        return new long[]{fields[0].charAt(0),Long.parseLong(fields[1]),Long.parseLong(fields[19])};
    }

    static String childState(OwnedChild child) {
        try {
            long[] stat=procStat(child.pid);
            if(stat[2]!=child.startTicks)return "identity_changed";
            return stat[0]=='Z'?"zombie":Character.toString((char)stat[0]);
        } catch(NoSuchFileException gone) {
            return "absent";
        } catch(Exception unknown) {
            return "unknown";
        }
    }

    static boolean originalChildExited(OwnedChild child) {
        String state=childState(child);
        child.finalState=state;
        return !child.handle.isAlive() && (state.equals("absent") || state.equals("identity_changed"));
    }

    static void rememberNativeChildren(Map<String,OwnedChild> owned,String phase) throws Exception {
        for(ProcessHandle handle:ProcessHandle.current().descendants().toList()) {
            if(!handle.isAlive())continue;
            long[] stat;
            try { stat=procStat(handle.pid()); }
            catch(NoSuchFileException gone) {
                if(!handle.isAlive())continue;
                throw gone;
            }
            String key=handle.pid()+":"+stat[2];
            if(!owned.containsKey(key))owned.put(key,new OwnedChild(handle,stat,phase));
        }
    }

    static void confirmLiveOwnedChild(OwnedChild child) throws Exception {
        if(!child.handle.isAlive())throw new IllegalStateException("native child exited before signal");
        ProcessHandle current=ProcessHandle.of(child.pid).orElseThrow();
        if(!current.info().startInstant().map(Object::toString).orElse("").equals(child.started) ||
                procStat(child.pid)[2]!=child.startTicks)
            throw new IllegalStateException("native child start identity changed before signal");
        boolean descendant=ProcessHandle.current().descendants().anyMatch(candidate->
            candidate.pid()==child.pid &&
            candidate.info().startInstant().map(Object::toString).orElse("").equals(child.started));
        if(!descendant)throw new IllegalStateException("native child is no longer in the private JVM tree");
    }

    static void awaitOwnedExit(OwnedChild child,long deadline) throws Exception {
        if(originalChildExited(child))return;
        long remaining=deadline-System.nanoTime();
        if(remaining<=0)return;
        try { child.handle.onExit().get(remaining,TimeUnit.NANOSECONDS); }
        catch(java.util.concurrent.TimeoutException pending) { }
        originalChildExited(child);
    }

    static void cleanupNativeChildren(Map<String,OwnedChild> owned,Map<String,Object> report) throws Exception {
        rememberNativeChildren(owned,"after_program_release");
        List<OwnedChild> children=new ArrayList<>(owned.values());
        children.sort(Comparator.comparingInt((OwnedChild child)->child.depth).reversed());
        List<String> failures=new ArrayList<>();
        for(OwnedChild child:children) {
            child.beforeCleanup=childState(child);
            if(originalChildExited(child))continue;
            try {
                if(!child.beforeCleanup.equals("zombie")) {
                    confirmLiveOwnedChild(child);
                    child.termSent=child.handle.destroy();
                }
            } catch(Exception error) {
                if(!originalChildExited(child))child.failure=bounded(error.toString(),512);
            }
        }
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
        for(OwnedChild child:children) {
            try { awaitOwnedExit(child,deadline); }
            catch(Exception error) { child.failure=bounded(error.toString(),512); }
        }
        for(OwnedChild child:children) {
            if(originalChildExited(child))continue;
            try {
                if(!childState(child).equals("zombie")) {
                    confirmLiveOwnedChild(child);
                    child.killSent=child.handle.destroyForcibly();
                }
            } catch(Exception error) {
                if(!originalChildExited(child))child.failure=bounded(error.toString(),512);
            }
        }
        deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
        for(OwnedChild child:children) {
            try { awaitOwnedExit(child,deadline); }
            catch(Exception error) { child.failure=bounded(error.toString(),512); }
            if(!originalChildExited(child))failures.add(child.key+":"+child.finalState);
        }
        List<Map<String,Object>> observations=new ArrayList<>();
        for(OwnedChild child:children)observations.add(child.observation());
        System.err.println("HEPTA_NATIVE_CHILD_CLEANUP "+json(observations));
        if(ProcessHandle.current().descendants().anyMatch(ProcessHandle::isAlive))
            failures.add("private JVM retains live or unreaped descendants");
        if(children.size()>64)failures.add("native child observation budget exceeded");
        if(!failures.isEmpty())throw new IllegalStateException(
            "native child cleanup is unconfirmed: "+String.join(",",failures));
        report.put("native_child_cleanup_scope","private_bridge_jvm_all_descendants");
        report.put("native_child_cleanup_confirmed",true);
        report.put("native_children",observations);
        report.put("observed_native_children",children.size());
        report.put("observed_native_decompiler_children",children.stream().filter(OwnedChild::isDecompiler).count());
        report.put("observed_explicit_decompiler_candidates",children.stream().filter(child->child.explicitDecompilerCandidate).count());
        report.put("native_helper_observation_scope","live_descendants_at_phase_boundaries");
    }

    static void decompile(Program program,Function function,Map<String,Object> report,
            Map<String,OwnedChild> owned) throws Exception {
        DecompInterface decompiler=new DecompInterface();
        TimeoutTaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(DECOMPILE_SECONDS,TimeUnit.SECONDS);
        rememberNativeChildren(owned,"before_selected_decompiler_open");
        Set<String> existing=new HashSet<>(owned.keySet());
        try {
            if(!decompiler.openProgram(program))
                throw new IllegalStateException("fixed native decompiler could not open the selected program");
            rememberNativeChildren(owned,"selected_decompiler_open");
            for(var entry:owned.entrySet()) {
                OwnedChild child=entry.getValue();
                if(!existing.contains(entry.getKey()) && child.isDecompiler())
                    child.explicitDecompilerCandidate=true;
            }
            DecompileResults result=decompiler.decompileFunction(function,DECOMPILE_SECONDS,monitor);
            monitor.checkCancelled();
            if(result==null || !result.decompileCompleted() || result.getDecompiledFunction()==null)
                throw new IllegalStateException("selected function decompilation did not complete: "+
                    (result==null?"no result":bounded(result.getErrorMessage(),1024)));
            String code=result.getDecompiledFunction().getC();
            byte[] encoded=code.getBytes(StandardCharsets.UTF_8);
            if(encoded.length>1024*1024)throw new IllegalStateException("decompiled C exceeds the fixed observation budget");
            String preview=bounded(code,8192);
            report.put("c_code",preview);
            report.put("c_code_sha256",digest(encoded));
            report.put("c_code_preview_sha256",digest(preview));
            report.put("c_code_utf8_bytes",encoded.length);
            report.put("c_code_complete",code.equals(preview));
            report.put("decompilation_completed",true);
            report.put("decompilation_timeout_seconds",DECOMPILE_SECONDS);
            report.put("decompiler_message",bounded(result.getErrorMessage(),1024));
        } finally {
            monitor.cancel();
            decompiler.stopProcess();
            decompiler.closeProgram();
            decompiler.dispose();
        }
    }

    @SuppressWarnings("unchecked")
    static String fit(Map<String,Object> report,int budget) throws Exception {
        while(true) {
            String encoded=json(report);
            if(encoded.getBytes(StandardCharsets.UTF_8).length+1<=budget)return encoded;
            String operation=(String)report.get("operation");
            if(operation.equals("functions")) {
                List<?> rows=(List<?>)report.get("functions"),external=(List<?>)report.get("external_functions");
                if(rows.isEmpty() && external.isEmpty())throw new IllegalStateException("analysis summary exceeds response budget");
                List<?> trimmed=rows.size()>=external.size()?rows:external;
                trimmed.subList(trimmed.size()/2,trimmed.size()).clear();
                report.put("returned_functions",rows.size());
                report.put("omitted_functions_in_scan",(Integer)report.get("scanned_functions")-rows.size());
                report.put("returned_external_functions",external.size());
                report.put("omitted_external_functions_in_scan",(Integer)report.get("scanned_external_functions")-external.size());
            } else if(operation.equals("xrefs")) {
                List<?> incoming=(List<?>)report.get("incoming_references"),outgoing=(List<?>)report.get("outgoing_references");
                if(incoming.isEmpty() && outgoing.isEmpty())
                    throw new IllegalStateException("analysis summary exceeds response budget");
                List<?> rows=incoming.size()>=outgoing.size()?incoming:outgoing;
                rows.subList(rows.size()/2,rows.size()).clear();
                report.put("returned_incoming_references",incoming.size());
                report.put("returned_outgoing_references",outgoing.size());
                report.put("omitted_incoming_references_in_scan",(Integer)report.get("scanned_incoming_references")-incoming.size());
                report.put("omitted_outgoing_references_in_scan",(Integer)report.get("scanned_outgoing_references")-outgoing.size());
            } else if(operation.equals("decompile")) {
                String code=(String)report.get("c_code");
                if(code.isEmpty())throw new IllegalStateException("analysis summary exceeds response budget");
                code=bounded(code,code.length()/2);
                report.put("c_code",code);
                report.put("c_code_preview_sha256",digest(code));
                report.put("c_code_complete",false);
            } else throw new IllegalStateException("selected function summary exceeds response budget");
        }
    }

    public static void main(String[] input) throws Exception {
        if(input.length!=5)throw new IllegalArgumentException("fixed installation, captured ELF, response budget, operation and address required");
        int budget=Integer.parseInt(input[2]);
        String operation=input[3],selected=input[4];
        if(budget<2048 || budget>65536)throw new IllegalArgumentException("invalid response budget");
        if(!List.of("functions","function","decompile","xrefs").contains(operation))
            throw new IllegalArgumentException("unsupported fixed analysis operation");
        if(operation.equals("functions")?!selected.equals("-"):!validAddress(selected))
            throw new IllegalArgumentException("one canonical internal function address is required for this operation");
        byte[] bytes=Files.readAllBytes(Path.of(input[1]));
        if(bytes.length<4 || bytes.length>8*1024*1024 || bytes[0]!=0x7f || bytes[1]!='E' || bytes[2]!='L' || bytes[3]!='F')
            throw new IllegalArgumentException("bounded captured ELF required");
        PrintStream result=System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        var config=new HeadlessGhidraApplicationConfiguration();
        config.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(new File(input[0])),config);
        if(!Application.getApplicationVersion().equals("12.1.4"))throw new IllegalStateException("unexpected Ghidra version");
        var loader=ProgramLoader.builder().source(new ByteArrayProvider("hepta-owned-input",bytes)).name("hepta-owned-input")
            .loaders(ElfLoader.class)
            .addLoaderArg("-loader-loadLibraries","false")
            .addLoaderArg("-loader-linkExistingProjectLibraries","false");
        Map<String,Object> report=new LinkedHashMap<>();
        Map<String,OwnedChild> owned=new LinkedHashMap<>();
        Throwable primaryFailure=null;
        try {
            try(var loaded=loader.load()) {
                Program program=loaded.getPrimary().getDomainObject();
                report.put("schema","hepta.rea.ghidra-analysis.v2");
                report.put("bridge_revision",4);
                report.put("engine_version",Application.getApplicationVersion());
                report.put("operation",operation);
                report.put("analysis_profile","hepta.ghidra.12.1.4.elf-x86_64-default-functions.v1");
                report.put("source_sha256",digest(bytes));
                report.put("source_bytes",bytes.length);
                report.put("function_address_requested",operation.equals("functions")?null:selected);
                report.put("loader","ghidra.app.util.opinion.ElfLoader");
                report.put("format",program.getExecutableFormat());
                report.put("language_id",program.getLanguageID().toString());
                report.put("compiler_spec_id",program.getCompilerSpec().getCompilerSpecID().toString());
                report.put("image_base",address(program.getImageBase()));
                report.put("target_executed",false);
                report.put("auto_analysis_performed",true);
                report.put("decompilation_performed",operation.equals("decompile"));
                report.put("decompilation_scope","explicit_selected_function");
                report.put("auto_analysis_may_decompile",true);
                report.put("source_semantics_validated",false);
                report.put("external_libraries_loaded",false);
                report.put("project_saved",false);
                report.put("coverage","partial");
                analyze(program,report);
                rememberNativeChildren(owned,"after_analysis");
                if(operation.equals("functions"))functions(program,report);
                else {
                    long offset=Long.parseUnsignedLong(selected.substring(2),16);
                    Address requested=program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
                    // Reject truncated offsets before using the engine's containment lookup.
                    if(!address(requested).equals(selected))
                        throw new IllegalArgumentException("requested address exceeds the loaded address space");
                    Function function=program.getFunctionManager().getFunctionAt(requested);
                    if(function==null)function=program.getFunctionManager().getFunctionContaining(requested);
                    if(function==null || function.isExternal() || !function.getBody().contains(requested))
                        throw new IllegalArgumentException("requested address has no containing internal analyzed function");
                    Map<String,Object> row=functionRow(function);
                    selectedBody(function,row);
                    report.put("function",row);
                    report.put("function_resolution",function.getEntryPoint().equals(requested)?"entry":"containing");
                    if(operation.equals("xrefs"))xrefs(program,function,report);
                    if(operation.equals("decompile"))decompile(program,function,report,owned);
                }
                rememberNativeChildren(owned,"before_program_release");
            }
        } catch(Exception | Error failure) {
            primaryFailure=failure;
            throw failure;
        } finally {
            try { cleanupNativeChildren(owned,report); }
            catch(Exception | Error cleanupFailure) {
                if(primaryFailure!=null)primaryFailure.addSuppressed(cleanupFailure);
                else throw cleanupFailure;
            }
        }
        result.println(fit(report,budget));
    }
}
