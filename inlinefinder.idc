//
// Comments common inlines
// by tomsons26

#include <idc.idc>
#define THRESHOLD 10
#define THRESHOLD2 150

static Check_For_Pattern_Extra(function, pattern, extrapattern, extradir)
{
    auto ea;
    auto new_name, comment;
    auto found;

    for ( ea = FirstSeg(); ea != BADADDR;) {
        ea = FindBinary(ea, SEARCH_DOWN, pattern);
        if (ea == BADADDR) {
            break;
        }

        comment = 0;
        //if no pattern set proceed with comment
        if (extrapattern == "") {
            comment = 1;
        } else {

            found = FindBinary(ea, extradir, extrapattern);
            if (found != BADADDR) {
                Message("Inline Finder - Checked from %x got extra %s at %x\n", ea, extrapattern, found);
                //if found is more than a threshold thats far away enough, comment
                if (found > ea + THRESHOLD) {
                    comment = 1;
                //if found is less than a threshold thats far away enough, comment
                } else if (found < ea - THRESHOLD) {
                    comment = 1;
                //else the pattern was found too close so we don't comment
                } else {
                    comment = 0;
                }
            }
        }

        if (comment) { 
            Message("Inline Finder - Found %s at 0x%X\n", function, ea);
            new_name = form("       !!!!!INLINE!!!!!\n\n            Inlined Function is %s", function);
            MakeComm(ea, new_name);
        } else {
            Message("Inline Finder - Ignoring Found %s at 0x%X as it doesn't fit with requirements\n", function, ea);
        }
        ea = ea + 4;
    }
}

static Check_For_Pattern(function, pattern)
{
    Check_For_Pattern_Extra(function, pattern, "", 0);
}

//checks current location for a inline function within a threshold
static Check_Here_For_Pattern(function, pattern)
{
    auto ea;
    auto comment;
    auto found;

        comment = 0;
        ea = here;
        found = FindBinary(ea, SEARCH_DOWN, pattern);
        if (found == BADADDR) {
            Message("Inline Finder - No Pattern Found");
            return 0;
        }
        //if address more than found threshold
        if (ea > found - THRESHOLD2) {
            comment = 1;
        }
        
        if (comment) { 
            Message("Inline Finder - Found %s at 0x%X\n", function, found);
            
            auto current,start,Selection_End;
            Selection_End = found + (strlen(pattern) / 3);
            
            auto comnt;
            comnt = form("************** inline %s", function);
            ExtLinA(found,0, comnt);

            for (current = found; current!=BADADDR; current = NextHead(current, Selection_End))
            {
                //Sets the color, format is address, type, and color in hex as 0xBBGGRR
                if (SetColor(current,CIC_ITEM,0xFFFFAA)==0)
                {
                    Message("**SetColor function Error**\n") ; 
                }
            }
        } else {
            //Message("Inline Finder - Ignoring Found %s at 0x%X as it doesn't fit with requirements\n", function, found);
        }
        return comment;
}


static Comment_Inline()
{
    auto compiler;
    compiler = GetCharPrm(INF_COMPILER);
    if (compiler == COMP_WATCOM) {
        Check_For_Pattern("strlen", "29 C9 49 31 C0 F2 AE F7 D1 49");
        Check_For_Pattern("strcat", "57 2B C9 49 B0 00 F2 AE 4F 8A 06 88 07 3C 00 74 10 8A 46 01 83 C6 02 88 47 01 83 C7 02 3C 00 75 E8");
        Check_For_Pattern_Extra("strcpy", "74 ? 8A ? 01 83 ? 02 88 ? 01 83 ? 02", "F2 AE", SEARCH_UP | SEARCH_NEXT);
        Check_For_Pattern("strchr", "8A 06 3A C2 74 12 3C 00 74 0C 46 8A 06 3A C2 74 07 46 3C 00 75 EA 2B F6");
        Check_For_Pattern("memcmp", "31 C0 F3 A6 74 05 19 C0 83 D8 FF");
        Check_For_Pattern("memcpy", "57 89 C8 C1 E9 02 F2 A5 8A C8 80 E1 03 F2 A4 5F");
    }
    if (compiler == COMP_MS) {
        Message("Inline Finder - No patterns added yet!");
    }
}

#define CHECK(x, y) if (Check_Here_For_Pattern(x, y)) { return 1; }

//inline commenting seems pretty messy so lets try this instead
static Check_For_Inline()
{
    auto compiler;
    compiler = GetCharPrm(INF_COMPILER);
    if (compiler == COMP_WATCOM) {
        //Watcom inlines
        CHECK("strchr", "8A 06 3A C2 74 12 3C 00 74 0C 46 8A 06 3A C2 74 07 46 3C 00 75 EA 2B F6");
        CHECK("strlen", "29 C9 49 31 C0 F2 AE F7 D1 49");
        CHECK("strcat", "57 2B C9 49 B0 00 F2 AE 4F 8A 06 88 07 3C 00 74 10 8A 46 01 83 C6 02 88 47 01 83 C7 02 3C 00 75 E8");
        CHECK("strcpy", "74 ?? 8A ?? 01 83 ?? 02 88 ?? 01 83 ?? 02");
        CHECK("memcmp", "31 C0 F3 A6 74 05 19 C0 83 D8 FF");
        CHECK("memcpy", "57 89 C8 C1 E9 02 F2 A5 8A C8 80 E1 03 F2 A4 5F");   
        
        //Common Westwood inlines
        CHECK("Timer::Time()", "8B 1D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 83 FB FF 74 1F 8B 0D ?? ?? ?? ?? BB ?? ?? ?? ?? 85 C9 75 04 31 C0 EB 07 89 C8 E8 ?? ?? ?? 00")
    }
    if (compiler == COMP_MS) {
        Message("Inline Finder - No patterns added yet!");
    }  
}

static main()
{
    Check_For_Inline();
}