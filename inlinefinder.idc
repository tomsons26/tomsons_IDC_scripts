//
// Comments common inlines
// by tomsons26
// After the script has been run once you can execute it via Check_For_Inline() or
// add code to bind a keyboard combo to trigger it.
// There are some quirks to this script, sometimes it will go past the first inline
// and find something later this is because it searches for patterns in sequence
// when this happens tweak the threshold to a better fitting value

#include <idc.idc>
#define THRESHOLD 10
#define THRESHOLD2 150//tweak this if something gets skipped

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
            Message("Inline Finder - No Pattern Found\n");
            comment = 0;
        }
        //if address more than found threshold
        if (found != BADADDR) {
            if (ea > found - THRESHOLD2) {
            comment = 1;
            }
        }
        
        if (comment) { 
            Message("Inline Finder - Found %s at 0x%X\n", function, found);

            auto current,start,Selection_End;
            Selection_End = found + (strlen(pattern) / 3);

            auto comnt;
            comnt = form("************** inline %s", function);
            ExtLinA(ItemHead(found), 0, comnt);

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

//this define wrapper is so that it ends execution if it finds something,
//as else we could get overlaps or even long wait time until the entire db is parsed
#define CHECK(x, y) if (Check_Here_For_Pattern(x, y)) { return 1; }

//inline commenting seems pretty messy so lets try this instead
static Check_For_Inline()
{
    auto compiler;
    compiler = GetCharPrm(INF_COMPILER);
    if (compiler == COMP_WATCOM) {
        //Watcom inlines
        Check_Here_For_Pattern("strchr", "8A 06 3A C2 74 12 3C 00 74 0C 46 8A 06 3A C2 74 07 46 3C 00 75 EA 2B F6");
        Check_Here_For_Pattern("strlen", "29 C9 49 31 C0 F2 AE F7 D1 49");
        Check_Here_For_Pattern("strcat(note it has a inlined strcpy)", "57 2B C9 49 B0 00 F2 AE 4F 8A 06 88 07 3C 00 74 10 8A 46 01 83 C6 02 88 47 01 83 C7 02 3C 00 75 E8");
        Check_Here_For_Pattern("strcpy", "8A 06 88 07 3C 00 74 ? 8A ? 01 83 ? 02 88 ? 01 83 ? 02 3C 00 75 E8");
        Check_Here_For_Pattern("memcmp", "31 C0 F3 A6 74 05 19 C0 83 D8 FF");
        Check_Here_For_Pattern("memcpy", "57 89 C8 C1 E9 02 F2 A5 8A C8 80 E1 03 F2 A4 5F");   
        
        //Common Westwood inlines
        Check_Here_For_Pattern("MAYBE Timer::Time()", "83 ? FF 74 ? 8B ? ? ? ? ? ?");
        Check_Here_For_Pattern("Timer::Time()", "8B 1D ? ? ? ? 8B 15 ? ? ? ? 83 FB FF 74 ? 8B 0D ? ? ? ? BB ? ? ? ? 85 C9 75 04 31 C0 EB 07 89 C8 E8 ? ? ? 00");
        Check_Here_For_Pattern("Timer::Time()", "83 ? FF 74 12 8B 15 ? ? ? ? 29 ? 39 C2 73 04 29 D0 EB 02 31 C0");
        
        Check_Here_For_Pattern("Pixel_To_Lepton 1", "C1 E2 08 83 C2 0C ? 18 00 00 00 89 D0 C1 FA 1F F7 ?");
        Check_Here_For_Pattern("Pixel_To_Lepton 2", "C1 E2 08 ? 18 00 00 00 ? ? ? ? 89 ? ? D0 C1 FA 1F F7 ?");
        
        //noninlined version
        //Check_Here_For_Pattern("Lepton_To_Pixel", "80 00 00 00 89 D0 C1 FA 1F C1 E2 08 1B C2 C1 F8 08");
  
        //RAs inlined versions
        //Check_Here_For_Pattern("Lepton_To_Pixel", "C1 E0 03 8D 90 80 00 00 00 89 D0 C1 FA 1F C1 E2 08 1B C2 C1 F8 08"); 
        Check_Here_For_Pattern("Lepton_To_Pixel", "0F BF D0 8D 04 95 00 00 00 00 29 D0 C1 E0 03 8D 90 80 00 00 00 89 D0 C1 FA 1F C1 E2 08 1B C2 C1 F8"); 
        Check_Here_For_Pattern("Cell_To_Coord 1", "8B 45 ? 83 E0 7F 88 45 ? ? 45 ? 80 8B 45 ? C1 E0 12 B2 80 C1 E8 19 88 55 ? 88 45 ? 8B"); 
        Check_Here_For_Pattern("Cell_To_Coord 2", "8B 45 ? 83 E0 7F 88 45 ? ? 45 ? ? 80 C1 E0 12 ? ? ? C1 E8 19 88 ? ? 88 45 ? 8B");
        Check_Here_For_Pattern("MAYBE Coord_To_Cell", "? ? 81 ? 7F C0 ? ?");
        
    }
    if (compiler == COMP_MS) {
        Message("Inline Finder - No patterns added yet!");
    }  
}

static main()
{
    Check_For_Inline();
}