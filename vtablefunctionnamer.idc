#include <idc.idc>
#include "vtable.idc"
#include "ms_rtti.idc"

static GetAsciizStr(x)
{
  auto s,c;
  s = "";
  while (c=Byte(x))
  {
    s = form("%s%c",s,c);
    x = x+1;
  }
  return s;
}

// ??1?$CEventingNode@VCMsgrAppInfoImpl@@PAUIMsgrUser@@ABUtagVARIANT@@@@UAE@XZ
// ??_G CWin32Heap@ATL @@UAEPAXI@Z
// ATL::CWin32Heap::`scalar deleting destructor'(uint)
// .?AV?$CEventingNode@VCMsgrAppInfoImpl@@PAUIMsgrUser@@ABUtagVARIANT@@@@
// ??_7?$CEventingNode@VCMsgrAppInfoImpl@@PAUIMsgrUser@@ABUtagVARIANT@@@@6B@
// ??_G?$CEventingNode@VCMsgrAppInfoImpl@@PAUIMsgrUser@@ABUtagVARIANT@@@@@@UAEPAXI@Z

//
// Type Definitions
//
#define SN_constructor           1
#define SN_destructor            2
#define SN_vdestructor           3
#define SN_scalardtr             4
#define SN_vectordtr             5
/// Westwood code
#define VC_SDDTOR                6
#define VC_operatorEE            7
#define VC_Resize                8
#define VC_Clear                 9
#define VC_ID1                   10
#define VC_ID2                   11
#define DVC_Resize               12
#define DVC_Clear                13
#define GetClassID               14
#define QueryInterface           15
#define TCF_QueryInterface       16
#define TCF_AddRef               17
#define TCF_Release              18
#define TCF_CreateInstance       19
#define TCF_LockServer           20
#define Load                     21
#define Save                     22
#define DVC_OperatorEE           23

//
// Creates name for function
//
static MakeSpecialName(name, type, adj)
{

  auto basename;
  //.?AUA@@ = typeid(struct A)
  //basename = A@@
  basename = substr(name,4,-1);

//
// Type Definitions
//
  if (type==SN_constructor)
  {
    //??0A@@QAE@XZ = public: __thiscall A::A(void)
    if (adj==0)
      return "??0"+basename+"QAE@XZ";
    else
      return "??0"+basename+"W"+MangleNumber(adj)+"AE@XZ";
  }
  else if (type==SN_destructor)
  {
    //??1A@@QAE@XZ = "public: __thiscall A::~A(void)"
    if (adj==0)
      return "??1"+basename+"QAE@XZ";
    else
      return "??1"+basename+"W"+MangleNumber(adj)+"AE@XZ";
  }
  else if (type==SN_vdestructor)
  {
    //??1A@@UAE@XZ = public: virtual __thiscall A::~A(void)
    if (adj==0)
      return "??1"+basename+"UAE@XZ";
    else
      return "??1"+basename+"W"+MangleNumber(adj)+"AE@XZ";
  }
  else if (type==SN_scalardtr) //
  {
    //??_GA@@UAEPAXI@Z = public: virtual void * __thiscall A::`scalar deleting destructor'(unsigned int)
    if (adj==0)
      return "??_G"+basename+"UAEPAXI@Z";
    else
      return "??_G"+basename+"W"+MangleNumber(adj)+"AEPAXI@Z";
  }
  else if (type==SN_vectordtr)
  {
    //.?AUA@@ = typeid(struct A)
    //??_EA@@UAEPAXI@Z = public: virtual void * __thiscall A::`vector deleting destructor'(unsigned int)
    if (adj==0)
      return "??_E"+basename+"QAEPAXI@Z";
    else
      return "??_E"+basename+"W"+MangleNumber(adj)+"AEPAXI@Z";
  }

//
// Westwood Code
//  

// VectorClass SDDTOR
  else if (type==VC_SDDTOR) //
  {
    if (adj==0)
      return "??_G"+basename+"UAEPAXI@Z";
  }

// VectorClass Operator==
  else if (type==VC_operatorEE) //
  {
    if (adj==0)
      return "??8"+basename+"UBE_NABV0@@Z";
  }

// VectorClass Resize
  else if (type==VC_Resize) //
  {
    if (adj==0)
      return "?Resize@"+basename+"UAE_NHPBV@@@Z";
  }

// VectorClass Clear
  else if (type==VC_Clear) //
  {
    if (adj==0)
      return "?Clear@"+basename+"UAEXXZ";
  }

// VectorClass ID &
  else if (type==VC_ID1) //
  {
    if (adj==0)
      return "?ID@"+basename+"UAEHABQAV@@@Z";
  }

// VectorClass ID *
  else if (type==VC_ID2) //
  {
    if (adj==0)
      return "?ID@"+basename+"UAEHPBQAV@@@Z";
  }

// DynamicVectorClass Operator==
  else if (type==DVC_OperatorEE) //
  {
    if (adj==0)
      return "??8"+basename+"UBE_NABV0@@Z";
  }

// DynamicVectorClass Resize
  else if (type==DVC_Resize) //
  {
    if (adj==0)
      return "?Resize@"+basename+"UAE_NHPBQAV@@@Z";
  }

// DynamicVectorClass Clear
  else if (type==DVC_Clear) //
  {
    if (adj==0)
      return "?Clear@"+basename+"UAEHPBQAV@@@Z";
  }

// IPersist GetClassID
  else if (type==GetClassID) //
  {
    if (adj==0)
      return "?GetClassID@"+basename+"UAGJPAU_GUID@@@Z";
  }

// IUnknown QueryInterface
  else if (type==QueryInterface) //
  {
    if (adj==0)
      return "?QueryInterface@IRTTITypeInfo@"+basename+"UAGJABU_GUID@@PAPAX@Z";
  }

// TClassFactory QueryInterface
  else if (type==TCF_QueryInterface) //
  {
    if (adj==0)
      return "?QueryInterface@"+basename+"UAGJABU_GUID@@PAPAX@Z";
  }

// TClassFactory AddRef
  else if (type==TCF_AddRef) //
  {
    if (adj==0)
      return "?AddRef@"+basename+"UAGKXZ";
  }

// TClassFactory Release
  else if (type==TCF_Release) //
  {
    if (adj==0)
      return "?Release@"+basename+"UAGKXZ";
  }

// TClassFactory CreateInstance
  else if (type==TCF_CreateInstance) //
  {
    if (adj==0)
      return "?CreateInstance@"+basename+"UAGJPAUIUnknown@@ABU_GUID@@PAPAX@Z";
  }

// TClassFactory LockServer
  else if (type==TCF_LockServer) //
  {
    if (adj==0)
      return "?LockServer@"+basename+"UAGJH@Z";
  }

// IPersistStream Load
  else if (type==Load) //
  {
    if (adj==0)
      return "?Load@"+basename+"UAGJPAUIStream@@H@Z";
  }

// IPersistStream Save
  else if (type==Save) //
  {
    if (adj==0)
      return "?Save@"+basename+"UAGJPAUIStream@@H@Z";
  }
}

//
// 
//
static DumpNestedClass2(x, indent, contained, f)
{

  auto indent_str,i,a,n,p,s,off;
  indent_str="";i=0;

  while(i<indent)
  {
    indent_str=indent_str+"    ";
    i++;
  }
  i=0;
  //indent=indent+1;
  a = x;
  while(i<contained)
  {
    p = Dword(a);
    off = Dword(p+8);
    s = form("%.4X: ",off);
    //Message("%s%s%s\n", s, indent_str, GetClassName(p));
    fprintf(f, form("%s%s%s\n",s,indent_str,GetClassName(p)));
    n = Dword(p+4);
    if (n>0) //check numContainedBases
      DumpNestedClass2(a+4, indent+1, n, f); //nested classes following
    a=a+4*(n+1);
    i=i+n+1;
  }

}

//
// 
//
static Parse_CHD2(x, indent, f)
{
  auto indent_str,i,a,n,p,s,off;
  indent_str="";i=0;
  while(i<indent)
  {
    indent_str=indent_str+"    ";
    i++;
  }
  a = Dword(x+4);
  if ((a&3)==1)
    p = "(MI)";
  else if ((a&3)==2)
    p = "(VI)";
  else if ((a&3)==3)
    p = "(MI VI)";
  else
    p="(SI)";

  fprintf(f, form("%s%s\n",indent_str,p));
  a=Dword(x+12);
  n=Dword(x+8);
  DumpNestedClass2(a, indent, n, f);
}

//
// 
//
static GetTypeName2(col)
{
  auto x, s, c;
  //Message("GetTypeName2(%X)\n",col)
  x = Dword(col+12);
  if ((!x) || (x==BADADDR)) return "";
  return GetAsciizStr(x+8);
}

//
// 
//
static GetVtblName2(col)
{
  auto i, s, s2;
  s = GetTypeName2(col);
  i = Dword(col+16); //CHD
  i = Dword(i+4);  //Attributes
  if ((i&3)==0 && Dword(col+4)==0)
  { 
    //Single inheritance, so we don't need to worry about duplicate names (several vtables)
    s=substr(s,4,-1);
    return "??_7"+s+"6B@";
  }
  else //if ((i&3)==1) //multiple inheritance
  { 
    s2 = GetVtableClass(col);
    s2 = substr(s2,4,-1);
    s  = substr(s,4,-1);
    s = s+"6B"+s2+"@";
    return "??_7"+s;
  }
  return "";
}

//
//check if Dword(vtbl-4) points to typeinfo record and extract the type name from it
//
static IsValidCOL(col)
{
  auto x, s, c;
  x = Dword(col+12);
  if ((!x) || (x==BADADDR)) return "";
  x = Dword(x+8);
  if ((x&0xFFFFFF) == 0x413F2E) //.?A
    return 1;
  else
    return 0;
}

//
//
//
static funcStart(ea)
{
  if (GetFunctionFlags(ea) == -1)
    return -1;

  if ((GetFlags(ea)&FF_FUNC)!=0)
    return ea;
  else
    return PrevFunction(ea);
}

//
// Add ea to "Sorted Address List"
//
static AddAddr(ea)
{
  auto id, idx, val;
  
  if ( (id = GetArrayId("AddrList")) == -1 )
  {
    id  = CreateArray("AddrList");
    SetArrayLong(id, 0, ea);
    return;
  }

  for ( idx = GetFirstIndex(AR_LONG, id); idx != -1; idx = GetNextIndex(AR_LONG, id, idx) )
  {
    val = GetArrayElement(AR_LONG, id, idx);
    if ( val == ea )
      return;
    if ( val > ea )    // InSort
    {
      for ( ; idx != -1; idx = GetNextIndex(AR_LONG, id, idx) )
      {
        val = GetArrayElement(AR_LONG, id, idx);
        SetArrayLong(id, idx, ea);
        ea = val;
      }
    }
  }
  SetArrayLong(id, GetLastIndex(AR_LONG, id) + 1, ea);
}

//
//
//
static getArraySize(id)
{
  auto idx, count;
  count = 0;
  for ( idx = GetFirstIndex(AR_LONG, id); idx != -1; idx = GetNextIndex(AR_LONG, id, idx) )
  {
    count++;
  }
  return count;
}

//
//
//
static doAddrList(name,f)
{
  auto idx, id, val, ctr, dtr;
  id = GetArrayId("AddrList");
  ctr = 0; dtr = 0;
  if ( name!=0 && id != -1 )
  {
    Message("refcount:%d\n",getArraySize(id));
    if (getArraySize(id)!=2)
      return;
    for ( idx = GetFirstIndex(AR_LONG, id); idx != -1; idx = GetNextIndex(AR_LONG, id, idx) )
    {
      val = GetArrayElement(AR_LONG, id, idx);
      if (Byte(val)==0xE9)
        val = getRelJmpTarget(val);
      if ((substr(Name(val),0,3)=="??1"))
        dtr = val;
      else
        ctr = val;
    }
  }
  if (ctr!=0 && dtr!=0)
  {
    Message("  constructor at %a\n",ctr);
    fprintf(f, "  constructor: %08.8Xh\n",ctr);
    MakeName(ctr, MakeSpecialName(name,SN_constructor,0));
  }
  DeleteArray(GetArrayId("AddrList"));
}

//
//check if there's a vtable at a and dump into to f
//returns position after the end of vtable
//
static DoVtable(a,f)
{
  auto x,y,s,p,q,i,name;

  //check if it looks like a vtable
  y = GetVtableSize(a);
  if (y==0)
    return a+4;
  s = form("%08.8Xh: possible vtable (%d methods)\n", a, y);
  Message(s);
  fprintf(f,s);

  //check if it's named as a vtable
  name = Name(a);
  if (substr(name,0,4)!="??_7") name=0;
 
  x = Dword(a-4); 

  //otherwise try to get it from RTTI
  if (IsValidCOL(x))
  {
    Parse_Vtable(a);
    if (name==0)
      name = GetVtblName2(x);
    //only output object tree for main vtable
    if (Dword(x+4)==0)
      Parse_CHD2(Dword(x+16),0,f);
    MakeName(a, name);
  }

  if (name!=0)
  {
    s = Demangle(name, 0x00004006);
    Message("%s\n",s);
    fprintf(f, "%s\n", s);
    //convert vtable name into typeinfo name
    name = ".?AV"+substr(name, 4, strstr(name,"@@6B")+2);
  }
  {
    DeleteArray(GetArrayId("AddrList"));
    Message("  referencing functions: \n");
    fprintf(f,"  referencing functions: \n");
    q = 0; i = 1;
    for ( x=DfirstB(a); x != BADADDR; x=DnextB(a,x) )
    {
       p = funcStart(x);
       if (p!=-1)
       { 
         if (q==p) 
           i++;
         else
         {           
           if (q) {
             if (i>1) s = form("  %a (%d times)",q,i);
             else s = form("  %a",q);
             //if (strstr(Name(p),"sub_")!=0 && strstr(Name(p),"j_sub_")!=0)
             if (hasName(GetFlags(q)))
               s = s+" ("+Demangle(Name(q),8)+")";
             s = s+"\n";
             Message(s);fprintf(f,s);
             AddAddr(q);
           }
           i = 1;
           q = p;
         }
       }
    }

    if (q)
    {           
       if (i>1) s = form("  %a (%d times)",q,i);
       else s = form("  %a",q);
       if (hasName(GetFlags(q)))
         s = s+" ("+Demangle(Name(q),8)+")";
       s = s+"\n";
       Message(s);fprintf(f,s);
       AddAddr(q);
    }
    
    x = a;
    while (y>0)
    {
      p = Dword(x);
      if (GetFunctionFlags(p) == -1)
      {
        MakeCode(p);
        MakeFunction(p, BADADDR);
      }
      checkSDD(p,name,a,0,f);
      y--;
      x = x+4;
    }
    doAddrList(name,f);
    Message("\n");
    fprintf(f,"\n");
  }
  return x;
}

//
//
//
static scan_for_vtables(void)
{
  auto rmin, rmax, cmin, cmax, s, a, x, y,f;
  s = FirstSeg();
  f = fopen("objtree.txt","w");
  rmin = 0; rmax = 0;
  while (s!=BADADDR)
  {
    if (SegName(s)==".rdata")
    {
      rmin = s;
      rmax = NextSeg(s);
    }
    else if (SegName(s)==".text")
    {
      cmin = s;
      cmax = NextSeg(s);
    }
    s = NextSeg(s);
  }
  if (rmin==0) {rmin=cmin; rmax=cmax;}
  a = rmin;
  Message(".rdata: %08.8Xh - %08.8Xh, .text %08.8Xh - %08.8Xh\n", rmin, rmax, cmin, cmax);
  while (a<rmax)
  {
    x = Dword(a);
    if (x>=cmin && x<cmax) //methods should reside in .text
    {
       a = DoVtable(a,f);
    }
    else
      a = a + 4;
  }
  Message("Done\n");
  fclose(f);
}

//
//check for `scalar deleting destructor'
//
static checkSDD(x,name,vtable,gate,f)
{
  auto a,s,t;
  //Message("checking function at %a\n",x);

  t = 0; a = BADADDR;

  if ((name!=0) && (substr(Name(x),0,3)=="??_") && (strstr(Name(x),substr(name,4,-1))==4))
    name=0; //it's already named

  if (Byte(x)==0xE9 || Byte(x)==0xEB) {
    //E9 xx xx xx xx   jmp   xxxxxxx
    return checkSDD(getRelJmpTarget(x),name,vtable,1,f);
  }

  else if (matchBytes(x,"83E9??E9")) {
    //thunk
    //83 E9 xx        sub     ecx, xx
    //E9 xx xx xx xx  jmp     class::`scalar deleting destructor'(uint)
    a = getRelJmpTarget(x+3);
    Message("  %a: thunk to %a\n",x,a);
    t = checkSDD(a,name,vtable,0,f);
    if (t && name!=0)
    {
      //rename this function as a thunk
      MakeName(x, MakeSpecialName(name,t,Byte(x+2)));
    }
    return t;
  }

  else if (matchBytes(x,"81E9????????E9")) {
    //thunk
    //81 E9 xx xx xx xx        sub     ecx, xxxxxxxx
    //E9 xx xx xx xx           jmp     class::`scalar deleting destructor'(uint)
    a = getRelJmpTarget(x+6);
    Message("  %a: thunk to %a\n",x,a);
    t = checkSDD(a,name,vtable,0,f);
    if (t && name!=0)
    {
      //rename this function as a thunk
      MakeName(x, MakeSpecialName(name,t,Dword(x+2)));
    }
    return t;
  }

  else if (matchBytes(x,"568BF1E8????????F64424080174") && matchBytes(x+15+Byte(x+14),"8BC65EC20400"))
  {
    //56                             push    esi
    //8B F1                          mov     esi, ecx
    //E8 xx xx xx xx                 call    class::~class()
    //F6 44 24 08 01                 test    [esp+arg_0], 1
    //74 07                          jz      short @@no_free
    //56                             push    esi
    //                               
    //                           call operator delete();
    
    //   @@no_free:
    //8B C6                          mov     eax, esi
    //5E                             pop     esi
    //C2 04 00                       retn    4

    t = SN_scalardtr;
    a = getRelCallTarget(x+3);
    if (gate && Byte(a)==0xE9)
    {
      //E9 xx xx xx xx   jmp   xxxxxxx
      a = getRelJmpTarget(a);
    }
  }

  else if (matchBytes(x,"568BF1FF15????????F64424080174") && matchBytes(x+16+Byte(x+15),"8BC65EC20400"))
  {
    //56                             push    esi
    //8B F1                          mov     esi, ecx
    //FF 15 xx xx xx xx              call    class::~class() //dllimport
    //F6 44 24 08 01                 test    [esp+arg_0], 1
    //74 07                          jz      short @@no_free
    //56                             push    esi
    //                               
    //                           call operator delete();
    
    //   @@no_free:
    //8B C6                          mov     eax, esi
    //5E                             pop     esi
    //C2 04 00                       retn    4

    t = SN_scalardtr;
    /*a = getRelCallTarget(x+3);
    if (gate && Byte(a)==0xE9)
    {
      //E9 xx xx xx xx   jmp   xxxxxxx
      a = getRelJmpTarget(a);
    }*/
  }

  else if (matchBytes(x,"558BEC51894DFC8B4DFCE8????????8B450883E00185C0740C8B4DFC51E8????????83C4048B45FC8BE55DC20400") ||
           matchBytes(x,"558BEC51894DFC8B4DFCE8????????8B450883E00185C074098B4DFC51E8????????8B45FC8BE55DC20400"))
  {
    //55                             push    ebp
    //8B EC                          mov     ebp, esp
    //51                             push    ecx
    //89 4D FC                       mov     [ebp+var_4], ecx
    //8B 4D FC                       mov     ecx, [ebp+var_4]
    //E8 xx xx xx xx                 call    sub_10001099
    //8B 45 08                       mov     eax, [ebp+arg_0]
    //83 E0 01                       and     eax, 1
    //85 C0                          test    eax, eax
    //74 0C                          jz      short skip
    //8B 4D FC                       mov     ecx, [ebp+var_4]
    //51                             push    ecx
    //E8 F0 56 05 00                 call    operator delete(void *)
    //83 C4 04                       add     esp, 4
    //
    //               skip:
    //8B 45 FC                       mov     eax, [ebp+var_4]
    //8B E5                          mov     esp, ebp
    //5D                             pop     ebp
    //C2 04 00                       retn    4

    t = SN_scalardtr;
    a = getRelCallTarget(x+10);
    if (gate && Byte(a)==0xE9)
    {
      //E9 xx xx xx xx   jmp   xxxxxxx
      a = getRelJmpTarget(a);
    }
  }

  else if (matchBytes(x,"568D71??578D7E??8BCFE8????????F644240C01"))
  {
    //56                             push    esi
    //8D 71 xx                       lea     esi, [ecx-XX]
    //57                             push    edi
    //8D 7E xx                       lea     edi, [esi+XX]
    //8B CF                          mov     ecx, edi
    //E8 xx xx xx xx                 call    class::~class()
    //F6 44 24 0C 01                 test    [esp+4+arg_0], 1
    a = getRelCallTarget(x+10);
    if (gate && Byte(a)==0xE9)
    {
      a = getRelJmpTarget(a);
    }
    t=SN_scalardtr;
  }

  else if (matchBytes(x,"568DB1????????578DBE????????8BCFE8????????F644240C01"))
  {
    //56                             push    esi
    //8D B1 xx xx xx xx              lea     esi, [ecx-XX]
    //57                             push    edi
    //8D BE xx xx xx xx              lea     edi, [esi+XX]
    //8B CF                          mov     ecx, edi
    //E8 xx xx xx xx                 call    class::~class()
    //F6 44 24 0C 01                 test    [esp+4+arg_0], 1
    a = getRelCallTarget(x+16);
    if (gate && Byte(a)==0xE9)
    {
      a = getRelJmpTarget(a);
    }
    t = SN_scalardtr;
  }

  else if ((matchBytes(x,"F644240401568BF1C706") /*&& Dword(x+10)==vtable*/) || 
           (matchBytes(x,"8A442404568BF1A801C706") /*&& Dword(x+11)==vtable */) ||
           (matchBytes(x,"568BF1B9????????8B46??C706????????50E8????????8A442408C746??????????A801C706") /*&& Dword(x+11)==vtable */) || //Westwood SDTOR used for Blitters
           (matchBytes(x,"568BF18D4E14E8????????8A442408C706????????A801740956E8????????83C4048BC65E") /*&& Dword(x+11)==vtable */) || //Westwood SDTOR used for BSurface
           (matchBytes(x,"568BF1C706????????E8????????F64424080174") && matchBytes(x+21+Byte(x+20),"8BC65EC20400"))
          )
  {
    //F6 44 24 04 01                 test    [esp+arg_0], 1
    //56                             push    esi
    //8B F1                          mov     esi, ecx
    //  OR
    //8A 44 24 04                    mov     al, [esp+arg_0]
    //56                             push    esi
    //8B F1                          mov     esi, ecx
    //A8 01                          test    al, 1

    //C7 06 xx xx xx xx              mov     dword ptr [esi], xxxxxxx //offset vtable
    //                           <inlined destructor>
    //74 07                          jz      short @@no_free
    //56                             push    esi
    //E8 CA 2D 0D 00                 call    operator delete(void *)
    //59                             pop     ecx
    //   @@no_free:
    //8B C6                          mov     eax, esi
    //5E                             pop     esi
    //C2 04 00                       retn    4  
    t = SN_scalardtr;
  }

  else if (matchBytes(x,"538A5C2408568BF1F6C302742B8B46FC578D7EFC68????????506A??56E8") || 
           matchBytes(x,"538A5C2408F6C302568BF1742E8B46FC5768????????8D7EFC5068????????56E8"))
  {
     //53                            push    ebx
     //8A 5C 24 08                   mov     bl, [esp+arg_0]
     //56                            push    esi
     //8B F1                         mov     esi, ecx
     //F6 C3 02                      test    bl, 2
     //74 2B                         jz      short loc_100037F8
     //8B 46 FC                      mov     eax, [esi-4]
     //57                            push    edi
     //8D 7E FC                      lea     edi, [esi-4]
     //68 xx xx xx xx                push    offset class::~class(void)
     //50                            push    eax
     //6A xx                         push    xxh
     //56                            push    esi
     //E8 xx xx xx xx                call    `eh vector destructor iterator'(void *,uint,int,void (*)(void *))
    t = SN_vectordtr;
    Message("  vector deleting destructor at %a\n",x);
    if (name!=0)
    a = Dword(x+21);
    if (gate && Byte(a)==0xE9)
    {
      a = getRelJmpTarget(a);
    }
  }

//
//
// Westwood Signatures
//
// VectorClass scalar deleting destructor
  else if (
       matchBytes(x,"568BF18B4604C706????????85C074178A4E0D84C9741050E8????????83C404C746??????????8A442408C6460D00A801C746??????????740956E8????????83C4048BC65EC20400")
    || matchBytes(x,"568BF18B4604C706????????85C074228A4E0D84C9741B85C074108B48FC83C0FC4950E8????????83C404C746??????????8A442408C6460D00A801C746??????????740956E8????????83C4048BC65EC20400"))
  {
    t=VC_SDDTOR;
  }

// VectorClass/DynamicVectorClass Operator==
  else if (
       matchBytes(x,"53568B7108578B7C24103B7708752733D285F67E198B41048B4F042BC88B388B1C013BFB75104283C0??3BD67CEF5F5EB0015BC204005F5E32C05BC20400")
    || matchBytes(x,"568B7108578B7C240C3B7708752633D285F67E198B41048B4F042BC8668B38663B3C01750F4283C0023BD67CEF5FB0015EC204005F32C05EC20400")
    || matchBytes(x,"8B5424045356578B79088B42083BF8752333C085FF7E158B52048B71048A0C068A1C023ACB750D403BC77CF15F5EB0015BC204005F5E32C05BC20400")
    || matchBytes(x,"8B44240453568B71088B5008573BF2752D33D285F67E1F8B49048B400483C10483")
    || matchBytes(x,"8B4424045355568B5008578B79083BFA75??33F685FF7E??8B50048B4104"))

// Old, top one should pick up all these
//    || matchBytes(x,"8B4424045355568B5008578B79083BFA753733F685FF7E288B50048B41048D4A042BD08B188B2C023BDD751D8B58048B293BDD75144683C10883C0083BF77CE35F5E5DB0015BC204005F5E5D32C05BC20400") //VectorClass<class DiscreteDistributionClass has this
//    || matchBytes(x,"8B4424045355568B5008578B79083BFA755733F685FF7E488B50048B41048BEA8D4A042BE88A50108A590C3AD3753A8B108B1C283BD375318B50048B193BD375288B50088B59043BD3751E8B500C8B59083BD375144683C11483C0143BF77CC55F5E5DB0015BC204005F5E5D32C05BC20400")
//    || matchBytes(x,"8B4424045355568B5008578B79083BFA754133F685FF7E328B50048B41048D4A082BD08B188B2C023BDD75278B58048B69FC3BDD751D8B58088B293BDD75144683C10C83C00C3BF77CD95F5E5DB0015BC204005F5E5D32C05BC20400"))
//    || matchBytes(x,"8B4424045355568B5008578B79083BFA753933F685FF7E2A8B50048B41048BEA8D4A042BE88B108B1C283BD3751D8A50048A193AD375144683C10883C0083BF77CE35F5E5DB0015BC204005F5E5D32C05BC20400"))
  {
    t=VC_operatorEE;
  }

// VectorClass Resize
  else if (
       matchBytes(x,"53558B6C240C33DB56??????8B????84????????8B??241888????3B??")
    || matchBytes(x,"53558B6C240C5685ED578BF10F84????????8B5C2418C6460C0085DB750D55E8") // Simplified to pick up resize in VectorClass<class DiscreteDistributionClass //8BF8EB028BFB85FFC6460C0175095F5E5D32C05BC208008B460485C074398B4E083BE97D028BCD33C085C97E108B5604403BC18B5482FC895487FC7CF08A460D84C074138B460450E8????????83C404C746??????????33C0897E0485DB0F94C0896E0888460D5F5E5DB0015BC208008B168BCEFF520C5F5E5DB0015BC20800"))
    || matchBytes(x,"515355568B74241433DB573BF38BE90F84????????8B7C241C885D0C3BFB753E8D04B6C1E00250E8????????83C4043BC374258D56FF3BD37C188D4808428959F88959FC891989590488590883C1144A75EC89442410EB29895C2410EB238D4EFF3BCB7C188D4708418958F88958FC891889580488580883C0144975EC897C24108B442410C6450C013BC3750A5F5E5D32C05B59C20800395D0474468B55083BF27D028BD63BD37E2533C08B7D048B4C24108BF003F78D3C08B9????????83C0144AF3A575E58B7C241C8B742418385D0D740F8B550452E8????????83C404895D048B44241089750889450433C03BFB5F0F94C088450D5E5DB0015B59C208008B55008BCDFF520C5F5E5DB0015B59C20800")
    || matchBytes(x,"51538B5C240C555685DB578BF10F84????????8B6C241CC6460C0085ED75218BC3C1"))
  {
    t=VC_Resize;
  }
// VectorClass Clear
  else if (
       matchBytes(x,"53568BF133DB8B46043BC37411385E0D740C50E8????????83C404895E04885E0D895E085E5BC3")
    || matchBytes(x,"53568BF133DB8B46043BC3741C385E0D74173BC374108B48FC83C0FC4950E8????????83C404895E04885E0D895E085E5BC3"))
  {
    t=VC_Clear;
  }

// VectorClass/DynamicVectorClass ID &
  else if (
       matchBytes(x,"8A410C5684C0750633C05EC204008B510833C085D27E158B7424088B49048B363931740B4083C1??3BC27CF483C8FF5E")
    || matchBytes(x,"8B511033C05685D27E158B7424088B49048B363931740B4083C1??3BC27CF483C8FF5EC20400")
    || matchBytes(x,"8B511033C085D2567E178B7424088B4904668B36663931740B4083C1023BC27CF383C8FF5EC20400")
    || matchBytes(x,"8A410C53555684C05775095F5E5D33C05BC204008B510833C085D27E??8B??24148B4904")
    || matchBytes(x,"5355568B711033C05785F67E1F8B7C24148B49048B2F3929750A8A51048A5F043AD3740B4083C1083BC67CEA83C8FF5F5E5D5BC20400")
    || matchBytes(x,"8A410C53565784C075085F5E33C05BC204008B510833C085D27E??8B7424108B49")
    || matchBytes(x,"8B5110535533C0565785D27E??8B"))
 {
    t=VC_ID1;
  }
// VectorClass/DynamicVectorClass ID *
  else if (matchBytes(x,"8A410C84C0750533C0C204008B??24048B??042B????????"))

  {
    t=VC_ID2;
  }
// DynamicVectorClass<Class *>::Resize
  else if (
       matchBytes(x,"53558B6C240C5685ED578BF174??8B5C2418C6460C0085DB75??8D")
    || matchBytes(x,"538B5C2408555685DB578BF10F84????????8B6C2418C6460C0085ED75368D04DD????????50E8????????83C40485C0741E8D4BFF891885C98D78047C338D470441C700????????83C0084975F4EB2133FFEB1D8D4BFF895D0085C98D7D047C108D470441C700????????83C0084975F485FFC6460C010F84????????8B460485C074618B4E083BD97D028BCB33C085C97E1C8B5604403BC18B6CC2F8896CC7F88B54C2FC8954C7FC7CE88B6C24188A460D84C0742F8B460485C074218B48FC8D68FC68????????516A0850E8????????55E8????????8B6C241C83C404C746??????????33C0897E0485ED0F94C0895E0888460DEB078B168BCEFF520C8B46088B4E103BC17D038946105F5E5DB0015BC208005F5E5D32C05BC20800")
    || matchBytes(x,"5153??????????????????????0F84????????8B??241CC6??0C0085??75"))
  {
    t=DVC_Resize;
  }
// DynamicVectorClass<Class *>::Clear
  else if (
       matchBytes(x,"??????F133DB8B4604895E103BC37411385E0D740C50E8????????83C404895E04")
    || matchBytes(x,"53568BF133DB8B4604895E103BC3741C385E0D74173BC374108B48FC83C0FC4950E8????????83C404895E04885E0D895E085E5BC3"))
  {
    t=DVC_Clear;
  }

// IPersist GetClassID
  else if (matchBytes(x,"8B44240885C07508B8????????C208008B0D????????89088B15????????8950048B0D????????8948088B15????????89500C33C0C20800"))
  {
    t=GetClassID;
  }

// IUnknown::QueryInterface
  else if (
       matchBytes(x,"8B54240C5685D257750A5FB8????????5EC20C008B44241053B9????????BF????????8BF033DBF3A75B741C8BF0B9????????BF????????33C0F3A7740A5FB8????????5EC20C008B44240C8902508B08FF51045F33C05EC20C00")
    || matchBytes(x,"8B54240C??????08B8????????C20C00538B5C240C5657B9????????BF????????"))
  {
    t=QueryInterface;
  }

// TClassFactory::QueryInterface
  else if (matchBytes(x,"8B44240C5385C07509B8????????5BC20C008B54240C5657B9????????BF????????8BF233DBC700????????8B5C2410F3A774128BF2B9????????BF????????33D2F3A7750289188B085F85C95E7509B8????????5BC20C008B0353FF500433C05BC20C00"))
  {
    t=TCF_QueryInterface;
  }

// TClassFactory::AddRef
  else if (matchBytes(x,"8B44240483C00450FF15????????C20400"))
  {
    t=TCF_AddRef;
  }

// TClassFactory::Release
  else if (matchBytes(x,"56578B7C240C8D470450FF15????????8BF085F6750957E8????????83C4048BC65F5EC20400"))
  {
    t=TCF_Release;
  }

// TClassFactory::CreateInstance
  else if (
       matchBytes(x,"56578B7C241885FF750A5FB8????????5EC210008B442410C707????????85C0740A5FB8????????5EC21000") )
// Old sigs, the current one seems to be picked up properly so no need for these
//       matchBytes(x,"56578B7C241885FF750A5FB8????????5EC210008B442410C707????????85C0740A5FB8????????5EC210006A??E8????????83C40485C0740D8BC8E8????????8BF085F6750A5FB8????????5EC210008B4C24148B06575156FF108BF885FF7D098B166A018BCEFF52??8BC75F5EC21000")
//    || matchBytes(x,"56578B7C241885FF750A5FB8????????5EC210008B442410C707????????85C0740A5FB8????????5EC2100068????????E8????????83C40485C0740D8BC8E8????????8BF085F6750A5FB8????????5EC210008B4C24148B06575156FF108BF885FF7D098B166A018BCEFF52208BC75F5EC21000")
//    || matchBytes(x,"56578B7C241885FF750A5FB8????????5EC210008B442410C707????????85C0740A5FB8????????5EC2100068????????E8????????83C40485C0740F6A008BC8E8????????8BF085F6750A5FB8????????5EC210008B4C24148B06575156FF108BF885FF7D098B166A018BCEFF52208BC75F5EC21000")
//    || matchBytes(x,"56578B7C241885FF750A5FB8????????5EC210008B442410C707????????85C0740A5FB8????????5EC2100068????????E8????????83C40485C074116A006A008BC8E8????????8BF085F6750A5FB8????????5EC210008B4C24148B06575156FF108BF885FF7D098B166A018BCEFF52208BC75F5EC21000")
//    || matchBytes(x,"56578B7C241885FF750A5FB8????????5EC210008B442410C707????????85C0740A5FB8????????5EC2100068????????E8????????83C40485C074146A0068????????8BC8E8????????8BF085F6750A5FB8????????5EC210008B4C24148B06575156FF108BF885FF7D098B166A018BCEFF52208BC75F5EC21000")
//    || matchBytes(x,"56578B7C241885FF750A5FB8????????5EC210008B442410C707????????85C0740A5FB8????????5EC2100068????????E8????????83C40485C074176A006A006A006A006A008BC8E8????????8BF085F6750A5FB8????????5EC210008B4C24148B06575156FF108BF885FF7D098B166A018BCEFF52208BC75F5EC21000") )
{
    t=TCF_CreateInstance;
}

// TClassFactory::LockServer
  else if (matchBytes(x,"8B44240885C08B4424048B480474094189480433C0C208004989480433C0C20800"))
  {
    t=TCF_LockServer;
  }

// IPersistStream::Save
  else if (matchBytes(x,"8B44240C8B4C24088B542404505152E8????????85C07C0233C0C20C00"))
  {
    t=Save;
  }

// IPersistStream::Load
  else if (matchBytes(x,"8B442408568B7424085056E8????????85C07C??85F674"))
  {
    t=Load;
  }
// Blitter DTOR
  else if (
       matchBytes(x,"8B5424288B01528B542428528B542428528B542428528B542428528B542428528B542428528B542428528B542428528B54242852FF5004C22C00") // RLEBlitter
    || matchBytes(x,"8B54241C6A00528B542420528B542420528B5424208B01528B542420528B542420528B54242052FF5004C22000") // Blitter
    || matchBytes(x,"8B5424208B01528B5424206A00528B542424528B542424528B542424528B542424528B542424528B54242452FF5008C22000") ) // BlitTrans
  {
    t=SN_vdestructor;
  }


  // No clue whats this for
  if ( t > 0 ) {
 
    if ( t == SN_vectordtr ) {
      s = "vector";
    } else if ( t == SN_scalardtr ) {
      s = "scalar";
    }
 
    if (t == SN_vectordtr || t == SN_scalardtr) {
      Message("  %s deleting destructor at %a\n",s,x);
      fprintf(f, "  %s deleting destructor: %08.8Xh\n",s,x);
    }
 
    if (name!=0) {
      MakeName(x, MakeSpecialName(name,t,0));
    }
 
    if (t == SN_vectordtr || t == SN_scalardtr) {
      if (a!=BADADDR) {
        Message("  virtual destructor at %a\n",a);
        fprintf(f, "  destructor: %08.8Xh\n",a);
        if (name!=0) {
          MakeName(a, MakeSpecialName(name,SN_vdestructor,0));
        }
      }
      CommentStack(x, 4, "__flags$", -1);
    }
  }



  //TOOD, add argument naming for different functions





  return t;
}

//
//
//
static ParseVtbl2()
{
  auto a, n;
  a = ScreenEA();
  if (GetVtableSize(a)==0)
  {
    Warning("This location doesn't look like a vtable!");
    return;
  }
  if (!hasName(GetFlags(a)) && !IsValidCOL(Dword(a-4)))
  {
    n = AskStr("","Enter class name");
    if (n!=0)
      MakeName(a,"??_7"+n+"@@6B@");
  }
  DoVtable(a,0);
}

//
//
//
static AddHotkeys()
{
  AddHotkey("Ctrl-Alt-F7","ParseFI");
  AddHotkey("Ctrl-Alt-F8","ParseVtbl2");
  AddHotkey("Ctrl-Alt-F9","ParseExc");
  Message("Use Ctrl-Alt-F7 to parse FuncInfo\n");
  Message("Use Ctrl-Alt-F8 to parse vtable\n");
  Message("Use Ctrl-Alt-F9 to parse throw info\n");
}

//
//
//
static main(void)
{
  if(AskYN(1, "Do you wish to scan the executable for vtables/RTTI?"))
  {
    Message("Scanning...");
    scan_for_vtables();
    Message("See objtree.txt for the class list/hierarchy.\n");
    //Exec("objtree.txt");
  }
  AddHotkeys();
}