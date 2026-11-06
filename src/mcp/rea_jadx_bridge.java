// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Fixed bridge loaded from the runtime image; only the inspected bytes vary.
// Reflection keeps javac out of the engine class path: a URLClassLoader opens
// the already sealed JADX jar descriptor directly, with no temporary aliases.
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.lang.reflect.*;
import java.util.*;

class HeptaJadx {
    static ClassLoader loader;
    static Class<?> type(String name) throws Exception { return Class.forName(name,true,loader); }
    static Object make(String name) throws Exception { return type(name).getConstructor().newInstance(); }
    static Object call(Object owner,String method) throws Exception { return owner.getClass().getMethod(method).invoke(owner); }
    static void set(Object owner,String method,Class<?> argument,Object value) throws Exception { owner.getClass().getMethod(method,argument).invoke(owner,value); }
    static String digest(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    static String bounded(String text,int limit) {
        if(text.length()<=limit)return text;
        int end=limit;
        if(end>0 && Character.isHighSurrogate(text.charAt(end-1)))end--;
        return text.substring(0,end);
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
            for(var item:map.entrySet())parts.add(json(item.getKey().toString())+":"+json(item.getValue()));
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
        if(input.length!=4 || !Set.of("classes","sources").contains(input[2]))throw new IllegalArgumentException("fixed jar, artifact, operation and response budget required");
        int budget=Integer.parseInt(input[3]);
        if(budget<1024 || budget>65536)throw new IllegalArgumentException("invalid response budget");
        PrintStream result=System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        try(URLClassLoader engine=new URLClassLoader(new URL[]{URI.create("jar:file:"+input[0]+"!/").toURL()},ClassLoader.getPlatformClassLoader())) {
            loader=engine;
            Thread.currentThread().setContextClassLoader(engine);
            Object args=make("jadx.api.JadxArgs");
            set(args,"setInputFile",File.class,new File(input[1]));
            set(args,"setThreadsCount",int.class,1);
            set(args,"setSkipResources",boolean.class,true);
            set(args,"setSkipFilesSave",boolean.class,true);
            set(args,"setDeobfuscationOn",boolean.class,false);
            set(args,"setIncludeDependencies",boolean.class,false);
            Class<?> comments=type("jadx.api.CommentsLevel");
            set(args,"setCommentsLevel",comments,comments.getField("NONE").get(null));
            for(String[] rule:new String[][]{
                {"setGeneratedRenamesMappingFileMode","jadx.api.args.GeneratedRenamesMappingFileMode"},
                {"setUserRenamesMappingsMode","jadx.api.args.UserRenamesMappingsMode"}}) {
                Class<?> mode=type(rule[1]);
                set(args,rule[0],mode,mode.getField("IGNORE").get(null));
            }
            Class<?> pluginLoader=type("jadx.api.plugins.loader.JadxPluginLoader");
            Object plugins=java.lang.reflect.Proxy.newProxyInstance(engine,new Class<?>[]{pluginLoader},(proxy,method,arguments)-> {
                if(method.getName().equals("load"))return List.of(make("jadx.plugins.input.java.JavaInputPlugin"),make("jadx.plugins.input.dex.DexInputPlugin"));
                if(method.getName().equals("toString"))return "HeptaFixedJadxPlugins";
                return null;
            });
            set(args,"setPluginLoader",pluginLoader,plugins);
            Object decompiler=type("jadx.api.JadxDecompiler").getConstructor(type("jadx.api.JadxArgs")).newInstance(args);
            try(AutoCloseable close=(AutoCloseable)decompiler) {
                call(decompiler,"load");
                List<?> classes=(List<?>)call(decompiler,"getClassesWithInners");
                List<Object> ordered=new ArrayList<>(classes);
                ordered.sort(Comparator.comparing(cls->{try{return (String)call(cls,"getRawName");}catch(Exception e){throw new IllegalStateException(e);}}));
                List<Map<String,Object>> rows=new ArrayList<>();
                for(Object cls:ordered.subList(0,Math.min(ordered.size(),64))) {
                    Map<String,Object> row=new LinkedHashMap<>();
                    String name=(String)call(cls,"getRawName");
                    row.put("class_name",bounded(name,512));
                    row.put("class_name_complete",name.length()<=512);
                    row.put("class_name_sha256",digest(name.getBytes(StandardCharsets.UTF_8)));
                    List<?> methods=(List<?>)call(cls,"getMethods");
                    row.put("declared_methods",methods.size());
                    List<String> methodNames=new ArrayList<>();
                    boolean complete=methods.size()<=16;
                    for(Object method:methods.subList(0,Math.min(methods.size(),16))) {
                        String methodName=(String)call(method,"getFullName");
                        methodNames.add(bounded(methodName,256));
                        complete &= methodName.length()<=256;
                    }
                    row.put("method_name_previews",methodNames);
                    row.put("methods_complete",complete);
                    if(input[2].equals("sources")) {
                        String code=(String)call(cls,"getCode");
                        byte[] bytes=code.getBytes(StandardCharsets.UTF_8);
                        row.put("source_utf8_bytes",bytes.length);
                        row.put("source_sha256",digest(bytes));
                        row.put("source_preview",bounded(code,1024));
                        row.put("source_preview_complete",code.length()<=1024);
                        call(cls,"unload");
                    }
                    rows.add(row);
                }
                Map<String,Object> report=new LinkedHashMap<>();
                report.put("schema","hepta.rea.jadx-observation.v1");
                report.put("engine_version",type("jadx.api.JadxDecompiler").getMethod("getVersion").invoke(null));
                report.put("operation",input[2]);
                report.put("observed_class_count",classes.size());
                report.put("rows",rows);
                report.put("errors",call(decompiler,"getErrorsCount"));
                report.put("warnings",call(decompiler,"getWarnsCount"));
                report.put("target_executed",false);
                report.put("external_plugins_loaded",false);
                report.put("source_semantics_validated",false);
                report.put("coverage","partial");
                String encoded;
                while(true) {
                    report.put("returned_class_count",rows.size());
                    report.put("omitted_class_count",classes.size()-rows.size());
                    encoded=json(report);
                    if(encoded.getBytes(StandardCharsets.UTF_8).length+1<=budget)break;
                    if(rows.isEmpty())throw new IllegalStateException("JADX summary exceeds response budget");
                    rows.subList(rows.size()/2,rows.size()).clear();
                }
                result.println(encoded);
            }
        }
    }
}
