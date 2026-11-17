// Inventories the loaded Behemoth GDT.
// @author TheMalwareGuardian
// @category UEFI

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;

public class ScriptEvolve00BehemothTypeUniverse extends GhidraScript {
	static final int MAX_DEPTH=32;
	static class Fn {
		String owner, field, declared, name, ret; int off; boolean varargs;
		List<String> args=new ArrayList<>();
		String proto(){ return ret+" "+name+"("+String.join(", ",args)+(varargs?(args.isEmpty()?"...":", ..."):"")+")"; }
	}
	static class Fld { int off, ord, len; String name,type; Fn fn; }
	static class St {
		String name,path; int len; boolean union; List<Fld> fields=new ArrayList<>(), calls=new ArrayList<>();
		String fp(){ TreeSet<Integer>s=new TreeSet<>(); for(Fld f:calls)s.add(f.off); StringJoiner j=new StringJoiner(",","{","}"); for(int x:s)j.add(String.format("%X",x)); return j.toString(); }
	}

	DataTypeManager src; String srcName;
	Map<String,DataType> types=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
	Map<String,St> structs=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
	List<Fn> funcs=new ArrayList<>(), callFields=new ArrayList<>();
	Map<Integer,List<Fn>> byOff=new TreeMap<>(), byArgs=new TreeMap<>();
	int total,nStruct,nUnion,nEnum,nTypedef,nFunc,nPtr,nArray,nBuiltin,nOther,nCallableStruct;

	public void run() throws Exception {
		println("========================================================================");
		println(" Behemoth - GDT Type Universe");
		println("========================================================================\n");
		int pointerSize=currentProgram==null?-1:currentProgram.getDefaultPointerSize();
		String expectedArchive=pointerSize==8?"Behemoth_X64":pointerSize==4?"Behemoth_IA32":null;
		if(expectedArchive==null){ printerr("Unsupported program pointer size: "+pointerSize+". Expected 8 (X64) or 4 (IA32)."); return; }
		src=findBehemoth(expectedArchive);
		if(src==null){ printerr(expectedArchive+" datatype archive not found. Open "+expectedArchive+".gdt in Data Type Manager and rerun."); return; }
		srcName=safeName(src);
		println("      Program pointer size: "+pointerSize+" bytes");
		println("      Required archive: "+expectedArchive);
		println("[1/5] Locating datatype universe\n----------------------------------------------------------------------");
		println("      Source: "+srcName+"\n");
		println("[2/5] Indexing all datatypes\n----------------------------------------------------------------------");
		index(); counts(); println("");
		println("[3/5] Building callable-structure models\n----------------------------------------------------------------------");
		buildStructs(); buildIndexes();
		println("      Callable structures ......... "+nCallableStruct);
		println("      Callable fields ............. "+callFields.size());
		println("      Callable offsets indexed .... "+byOff.size());
		println("      Argument counts indexed ..... "+byArgs.size()+"\n");
		println("[4/5] Building structural fingerprints\n----------------------------------------------------------------------");
		St best=null; for(St s:structs.values()) if(best==null||s.calls.size()>best.calls.size())best=s;
		if(best!=null){ println("      Largest callable structure .. "+best.name); println("      Callable fields ............. "+best.calls.size()); println("      Fingerprint ................. "+best.fp()); }
		println("");
		println("[5/5] Writing report\n----------------------------------------------------------------------");
		File report=new File(System.getProperty("user.home"),"Behemoth_Type_Universe.txt"); writeReport(report);
		println("      Report saved: "+report.getAbsolutePath()+"\n");
		println("========================================================================\n Results\n========================================================================");
		println(String.format("      Types            %-8d  Structures       %d",total,nStruct));
		println(String.format("      Unions           %-8d  Enums            %d",nUnion,nEnum));
		println(String.format("      Typedefs         %-8d  Function defs    %d",nTypedef,nFunc));
		println(String.format("      Pointers         %-8d  Arrays           %d",nPtr,nArray));
		println(String.format("      Callable structs %-8d  Callable fields  %d",nCallableStruct,callFields.size()));
		println("========================================================================");
	}

	DataTypeManager findBehemoth(String expectedArchive){
		List<DataTypeManager> ms=new ArrayList<>();
		try{
			DataTypeManagerService s=state.getTool().getService(DataTypeManagerService.class);
			if(s!=null){ DataTypeManager[] a=s.getDataTypeManagers(); if(a!=null)ms.addAll(Arrays.asList(a)); }
		}catch(Throwable t){}
		for(DataTypeManager d:ms){
			if(d==null)continue;
			if(currentProgram!=null&&d==currentProgram.getDataTypeManager())continue;
			String n=safeName(d);
			String normalized=n.toLowerCase(Locale.ROOT);
			String wanted=expectedArchive.toLowerCase(Locale.ROOT);
			if(normalized.equals(wanted)||normalized.equals(wanted+".gdt"))return d;
		}
		return null;
	}

	int count(DataTypeManager d){int n=0;try{Iterator<DataType>i=d.getAllDataTypes();while(i.hasNext()&&n<20000){i.next();n++;}}catch(Throwable t){}return n;}
	String safeName(DataTypeManager d){try{return d.getName();}catch(Throwable t){return "<unnamed>";}}

	void index(){
		Iterator<DataType> it=src.getAllDataTypes();
		while(it.hasNext()&&!monitor.isCancelled()){
			DataType d=it.next(); if(d==null)continue; total++; types.putIfAbsent(path(d),d);
			if(d instanceof Structure)nStruct++;
			else if(d instanceof Union)nUnion++;
			else if(d instanceof ghidra.program.model.data.Enum)nEnum++;
			else if(d instanceof TypeDef)nTypedef++;
			else if(d instanceof FunctionDefinition){nFunc++;funcs.add(fn(null,null,-1,d.getName(),(FunctionDefinition)d));}
			else if(d instanceof Pointer)nPtr++;
			else if(d instanceof Array)nArray++;
			else if(d instanceof BuiltInDataType)nBuiltin++;
			else nOther++;
		}
	}
	void counts(){
		println("      Data types .................. "+total);
		println("      Structures .................. "+nStruct);
		println("      Unions ...................... "+nUnion);
		println("      Enums ....................... "+nEnum);
		println("      Typedefs .................... "+nTypedef);
		println("      Function definitions ........ "+nFunc);
		println("      Pointers .................... "+nPtr);
		println("      Arrays ...................... "+nArray);
		println("      Built-ins ................... "+nBuiltin);
		println("      Other ....................... "+nOther);
	}

	void buildStructs(){
		for(DataType d:types.values()){
			if(monitor.isCancelled())return;
			if(!(d instanceof Structure)&&!(d instanceof Union))continue;
			Composite c=(Composite)d; St s=new St(); s.name=d.getName();s.path=path(d);s.len=len(d);s.union=d instanceof Union;
			DataTypeComponent[] cs;
			try{cs=c.getDefinedComponents();}catch(Throwable t){cs=c.getComponents();}
			for(DataTypeComponent x:cs){
				if(x==null)continue; Fld f=new Fld();f.off=x.getOffset();f.ord=x.getOrdinal();f.len=x.getLength();f.name=fieldName(x);f.type=disp(x.getDataType());
				FunctionDefinition fd=unwrap(x.getDataType());
				if(fd!=null){f.fn=fn(s.name,f.name,f.off,f.type,fd);s.calls.add(f);callFields.add(f.fn);}
				s.fields.add(f);
			}
			if(!s.calls.isEmpty())nCallableStruct++;
			structs.put(s.path,s);
		}
	}
	FunctionDefinition unwrap(DataType d){
		Set<DataType> seen=Collections.newSetFromMap(new IdentityHashMap<DataType,Boolean>());
		for(int i=0;i<MAX_DEPTH&&d!=null;i++){
			if(!seen.add(d))return null;
			if(d instanceof FunctionDefinition)return (FunctionDefinition)d;
			if(d instanceof TypeDef){d=((TypeDef)d).getBaseDataType();continue;}
			if(d instanceof Pointer){d=((Pointer)d).getDataType();continue;}
			return null;
		}
		return null;
	}
	Fn fn(String owner,String field,int off,String declared,FunctionDefinition fd){
		Fn f=new Fn();f.owner=owner;f.field=field;f.off=off;f.declared=declared;f.name=fd.getName();f.ret=disp(fd.getReturnType());
		ParameterDefinition[] a=fd.getArguments();
		if(a!=null)for(ParameterDefinition p:a){if(p==null)continue;String x=disp(p.getDataType());String n=p.getName();f.args.add(n==null||n.isBlank()?x:x+" "+n);}
		try{f.varargs=fd.hasVarArgs();}catch(Throwable t){}
		return f;
	}
	void buildIndexes(){
		for(Fn f:callFields){byOff.computeIfAbsent(f.off,k->new ArrayList<>()).add(f);byArgs.computeIfAbsent(f.args.size(),k->new ArrayList<>()).add(f);}
		Comparator<Fn> c=Comparator.comparing((Fn f)->nz(f.owner),String.CASE_INSENSITIVE_ORDER).thenComparing(f->nz(f.field),String.CASE_INSENSITIVE_ORDER);
		for(List<Fn> l:byOff.values())l.sort(c);for(List<Fn> l:byArgs.values())l.sort(c);
	}

	void writeReport(File r)throws IOException{
		try(PrintWriter o=new PrintWriter(new OutputStreamWriter(new FileOutputStream(r),"UTF-8"))){
			o.println("========================================================================\n Behemoth - GDT Type Universe\n========================================================================");
			o.println("Source: "+srcName); if(currentProgram!=null)o.println("Program: "+currentProgram.getName()+"\nPointer size: "+currentProgram.getDefaultPointerSize());
			o.println("\n[SUMMARY]");o.println("Data types="+total);o.println("Structures="+nStruct);o.println("Unions="+nUnion);o.println("Enums="+nEnum);o.println("Typedefs="+nTypedef);o.println("Function definitions="+nFunc);o.println("Pointers="+nPtr);o.println("Arrays="+nArray);o.println("Built-ins="+nBuiltin);o.println("Other="+nOther);o.println("Callable structures="+nCallableStruct);o.println("Callable fields="+callFields.size());
			o.println("\n========================================================================\n CALLABLE STRUCTURES\n========================================================================\n");
			List<St> ss=new ArrayList<>();for(St s:structs.values())if(!s.calls.isEmpty())ss.add(s);
			ss.sort(Comparator.comparing((St s)->s.name,String.CASE_INSENSITIVE_ORDER).thenComparing(s->s.path,String.CASE_INSENSITIVE_ORDER));
			for(St s:ss){
				o.println("[Callable Structure]\nName: "+s.name+"\nPath: "+s.path+"\nKind: "+(s.union?"Union":"Structure"));
				o.printf("Size: 0x%X (%d)%nFields: %d%nCallable fields: %d%nFingerprint: %s%n%n",s.len,s.len,s.fields.size(),s.calls.size(),s.fp());
				for(Fld x:s.calls){Fn f=x.fn;o.printf("  +0x%X  %s%n",x.off,x.name);o.println("         Declared: "+x.type);o.println("         Function: "+f.name);o.println("         Return  : "+f.ret);o.println("         Args    : "+f.args.size()+(f.varargs?" + varargs":""));for(int i=0;i<f.args.size();i++)o.printf("             [%d] %s%n",i,f.args.get(i));o.println("         Proto   : "+f.proto()+"\n");}
				o.println("------------------------------------------------------------------------\n");
			}
			o.println("========================================================================\n REVERSE INDEX - CALLABLE OFFSET\n========================================================================\n");
			for(Map.Entry<Integer,List<Fn>>e:byOff.entrySet()){o.printf("[Offset +0x%X] candidates=%d%n",e.getKey(),e.getValue().size());for(Fn f:e.getValue())o.println("  "+f.owner+"::"+f.field+" -> "+f.proto());o.println();}
			o.println("========================================================================\n REVERSE INDEX - ARGUMENT COUNT\n========================================================================\n");
			for(Map.Entry<Integer,List<Fn>>e:byArgs.entrySet()){o.printf("[Arguments %d] candidates=%d%n",e.getKey(),e.getValue().size());for(Fn f:e.getValue())o.printf("  %s::%s @ +0x%X -> %s%n",f.owner,f.field,f.off,f.proto());o.println();}
			o.println("========================================================================\n ALL STRUCTURES / UNIONS\n========================================================================\n");
			List<St> all=new ArrayList<>(structs.values());all.sort(Comparator.comparing((St s)->s.name,String.CASE_INSENSITIVE_ORDER).thenComparing(s->s.path,String.CASE_INSENSITIVE_ORDER));
			for(St s:all)o.printf("%s | %s | size=0x%X | fields=%d | callable=%d | fingerprint=%s%n",s.union?"UNION":"STRUCT",s.path,s.len,s.fields.size(),s.calls.size(),s.fp());
			o.println("\n========================================================================\n STANDALONE FUNCTION DEFINITIONS\n========================================================================\n");
			funcs.sort(Comparator.comparing((Fn f)->f.name,String.CASE_INSENSITIVE_ORDER));for(Fn f:funcs)o.println(f.proto());
		}
	}
	String fieldName(DataTypeComponent c){String n=c.getFieldName();if(n==null||n.isBlank())n=c.getDefaultFieldName();if(n==null||n.isBlank())n="field_"+Integer.toHexString(c.getOffset()).toUpperCase(Locale.ROOT);return n;}
	int len(DataType d){try{return d.getLength();}catch(Throwable t){return -1;}}
	String path(DataType d){try{DataTypePath p=d.getDataTypePath();if(p!=null)return p.getPath();}catch(Throwable t){}return d.getName();}
	String disp(DataType d){if(d==null)return "<null>";try{String x=d.getDisplayName();if(x!=null&&!x.isBlank())return x;}catch(Throwable t){}return d.getName();}
	String nz(String s){return s==null?"":s;}
}
