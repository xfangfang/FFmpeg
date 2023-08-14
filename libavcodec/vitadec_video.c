#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <psp2/videodec.h>
#include <psp2/kernel/sysmem.h>

#include "decode.h"
#include "avcodec.h"
#include "internal.h"
#include "codec_internal.h"

#include "h264_ps.h"
#include "h264_parse.h"
#include "h2645_parse.h"
#include "startcode.h"

#include "libavutil/log.h"
#include "libavutil/macros.h"
#include "libavutil/imgutils.h"
#include "libavutil/mathematics.h"

// non-exported internal API

typedef struct SceVideodecCtrl {
    uint8_t reserved[24];
    SceUIntVAddr vaddr;
    SceUInt32 size;
} SceVideodecCtrl;

SceInt32 sceAvcdecDecodeFlush(SceAvcdecCtrl *ctrl);
SceInt32 sceAvcdecDecodeStop(SceAvcdecCtrl *ctrl, SceAvcdecArrayPicture *pictures);

SceUID sceCodecEngineOpenUnmapMemBlock(void *ptr, SceSize size);
SceInt32 sceCodecEngineCloseUnmapMemBlock(SceUID uid);

SceUIntVAddr sceCodecEngineAllocMemoryFromUnmapMemBlock(SceUID uid, SceUInt32 size, SceUInt32 align);
SceInt32 sceCodecEngineFreeMemoryFromUnmapMemBlock(SceUID uid, SceUIntVAddr p);

void sceAvcdecSetDecodeMode(SceVideodecType type, SceInt32 mode);
void sceVideodecSetConfigInternal(SceVideodecType type, SceInt32 cfg);

void sceVideodecQueryMemSizeInternal(SceVideodecType type, SceVideodecQueryInitInfo *query, SceUInt32 *size);
SceInt32 sceAvcdecQueryDecoderMemSizeInternal(SceVideodecType type, SceAvcdecQueryDecoderInfo *query, SceAvcdecDecoderInfo *decoder);

SceInt32 sceVideodecInitLibraryWithUnmapMemInternal(SceVideodecType type, SceVideodecCtrl *ctrl, SceVideodecQueryInitInfo *query);
SceInt32 sceAvcdecCreateDecoderInternal(SceVideodecType type, SceAvcdecCtrl *decoder, SceAvcdecQueryDecoderInfo *query);

SceInt32 sceAvcdecDecodeAuInternal(SceAvcdecCtrl *decoder, SceAvcdecAu *au, SceInt32 *pic);
SceInt32 sceAvcdecDecodeGetPictureWithWorkPictureInternal(SceAvcdecCtrl *decoder, SceAvcdecArrayPicture *a1, SceAvcdecArrayPicture *a2, SceInt32 *pic);

// | Frame | Output | Codec | Time-NoCopy | Time-CopyOut |
// |-------|--------|-------|-------------|--------------|
// | CDRAM | CDRAM  | CDRAM | 2.419       | 3.686        |
// | PHY   | PHY    | PHY   | 2.747       | 2.917        |
// | PHY   | CDRAM  | CDRAM | 2.556       | 4.343        |
// | CDRAM | PHY    | CDRAM | 2.460       | 2.936        |
// | CDRAM | CDRAM  | PHY   | 2.467       | 3.733        |
//
// These buffers can be allocated in either PHY or CDRAM memory. 
// The sample is a 20-second 540x360 mp4, which has 200 packets.
//
// Although PHY memory can improve performance a little bit, 
// it is too scarce (only 26MB available) to hold all buffers 
// in high resolution video decoding, so CDRAM is a better choice.

#define VITA_DECODE_MEM_BLOCK_NAME              "ffmpeg_vdec"
#define VITA_DECODE_MEM_BLOCK_TYPE              SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW
#define VITA_DECODE_MEM_BLOCK_SIZE_ALIGN        (256 * 1024)
#define VITA_DECODE_TIMESTAMP_UNIT_BASE         (90 * 1000)
#define VITA_DECODE_TIMESTAMP_VOID              (0xffffffff)

#define VITA_DECODE_VIDEO_FLAG_INIT_POSTPONED           1
#define VITA_DECODE_VIDEO_FLAG_DECODER_READY            (1 << 1)
#define VITA_DECODE_VIDEO_FLAG_DONE_AVC_LIB             (1 << 2)
#define VITA_DECODE_VIDEO_FLAG_DONE_DECODER             (1 << 3)
#define VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_FRAME        (1 << 4)
#define VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_OUTPUT       (1 << 5)
#define VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_CODEC_MB     (1 << 6)
#define VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_CODEC_UNMAP  (1 << 7)
#define VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_CODEC_VADDR  (1 << 8)

enum VitaDecodeBufferType {
    VITA_DECODE_BUFFER_TYPE_FRAME,
    VITA_DECODE_BUFFER_TYPE_OUTPUT,
    VITA_DECODE_BUFFER_TYPE_CODEC_MEM,
    VITA_DECODE_BUFFER_TYPE_CODEC_UNMAP,
    VITA_DECODE_BUFFER_TYPE_CODEC_VADDR,
    VITA_DECODE_BUFFER_TYPE_NB,
};

typedef struct VitaDecodeFormatDescriptor {
    enum AVPixelFormat ff_format;
    SceAvcdecPixelFormat sce_format;
    int pitch_alignment;
} VitaDecodeFormatDescriptor;

typedef struct VitaDecodeBufferAllocParams {
    SceUID *mb;
    void *ptr;
    void *ref;
    int size;
    int alignment;
} VitaDecodeBufferAllocParams;

typedef struct VitaDecodeBufferFreeParams {
    SceUID *mb;
    void *ptr;
    void *ref;
} VitaDecodeBufferFreeParams;

typedef struct VitaDecodeBufferDescriptor {
    bool (*alloc)(VitaDecodeBufferAllocParams *p);
    void (*free)(VitaDecodeBufferFreeParams *p);
    const char *name;
    int field_bit;
    int offset_mb;
    int offset_ptr;
    int offset_ref;
    int alignment_addr;
    int alignment_size;
} VitaDecodeBufferDescriptor;

typedef struct VitaDecodeContextImpl {
    int flags;

    int frame_width;
    int frame_height;
    int frame_pitch;
    const VitaDecodeFormatDescriptor *frame_format;

    SceUID decoder_mb_frame;
    SceUID decoder_mb_output;
    SceUID decoder_mb_codec_mem;
    SceUID decoder_mb_codec_unmap;
    SceUIntVAddr decoder_vaddr_codec;
    void *decoder_ptr_codec_mem;
    void *decoder_ptr_output;
    int decoder_picture_int;
    SceAvcdecCtrl decoder_ctrl;

    int h264_width;
    int h264_height;
    int h264_ref_frames;
} VitaDecodeContextImpl;

typedef struct VitaDecodeContext {
    AVClass *clz;
    VitaDecodeContextImpl impl;
} VitaDecodeContext;


static bool do_mem_alloc(VitaDecodeBufferAllocParams *p);
static void do_mem_free(VitaDecodeBufferFreeParams *p);
static bool do_unmap_open(VitaDecodeBufferAllocParams *p);
static void do_unmap_close(VitaDecodeBufferFreeParams *p);
static bool do_vaddr_alloc(VitaDecodeBufferAllocParams *p);
static void do_vaddr_free(VitaDecodeBufferFreeParams *p);

static void do_init(AVCodecContext *avctx);
static void buffers_free(AVCodecContext *avctx);


static const VitaDecodeFormatDescriptor vita_decode_format_descriptors[] = {
    { AV_PIX_FMT_RGBA, SCE_AVCDEC_PIXELFORMAT_RGBA8888, 16 },
    { AV_PIX_FMT_BGR565LE, SCE_AVCDEC_PIXELFORMAT_RGBA565, 16 },
    { AV_PIX_FMT_BGR555LE, SCE_AVCDEC_PIXELFORMAT_RGBA5551, 16 },
    { AV_PIX_FMT_YUV420P, SCE_AVCDEC_PIXELFORMAT_YUV420_RASTER, 32 },
    { AV_PIX_FMT_NV12, SCE_AVCDEC_PIXELFORMAT_YUV420_PACKED_RASTER, 16 },
};

static const VitaDecodeBufferDescriptor vita_decode_buffer_descriptors[VITA_DECODE_BUFFER_TYPE_NB] = {
    [VITA_DECODE_BUFFER_TYPE_FRAME] = {
        do_mem_alloc,
        do_mem_free,
        "frame",
        VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_FRAME,
        offsetof(VitaDecodeContextImpl, decoder_mb_frame),
        0,
        0,
        (1024 * 1024),
        0,
    },

    [VITA_DECODE_BUFFER_TYPE_OUTPUT] = {
        do_mem_alloc,
        do_mem_free,
        "output",
        VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_OUTPUT,
        offsetof(VitaDecodeContextImpl, decoder_mb_output),
        offsetof(VitaDecodeContextImpl, decoder_ptr_output),
        0,
        0,
        0,
    },

    [VITA_DECODE_BUFFER_TYPE_CODEC_MEM] = {
        do_mem_alloc,
        do_mem_free,
        "codec_mb",
        VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_CODEC_MB,
        offsetof(VitaDecodeContextImpl, decoder_mb_codec_mem),
        offsetof(VitaDecodeContextImpl, decoder_ptr_codec_mem),
        0,
        (1024 * 1024),
        (1024 * 1024),
    },

    [VITA_DECODE_BUFFER_TYPE_CODEC_UNMAP] = {
        do_unmap_open,
        do_unmap_close,
        "codec_unmap",
        VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_CODEC_UNMAP,
        offsetof(VitaDecodeContextImpl, decoder_mb_codec_unmap),
        0,
        offsetof(VitaDecodeContextImpl, decoder_ptr_codec_mem),
        0,
        (1024 * 1024),
    },

    [VITA_DECODE_BUFFER_TYPE_CODEC_VADDR] = {
        do_vaddr_alloc,
        do_vaddr_free,
        "codec_vaddr",
        VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_CODEC_VADDR,
        0,
        offsetof(VitaDecodeContextImpl, decoder_vaddr_codec),
        offsetof(VitaDecodeContextImpl, decoder_mb_codec_unmap),
        0,
        (256 * 1024),
    },
};


static bool do_mem_alloc(VitaDecodeBufferAllocParams *p)
{
    SceUID mb = -1;
    void *ptr = NULL;
    SceUID *out_mb = p->mb;
    void **out_ptr = p->ptr;
    SceKernelAllocMemBlockOpt opt = {0};
    SceKernelAllocMemBlockOpt *arg = NULL;

    if (p->alignment) {
        arg = &opt;
        arg->size = sizeof(SceKernelAllocMemBlockOpt);
        arg->attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_ALIGNMENT;
        arg->alignment = p->alignment;
    }

    p->size = FFALIGN(p->size, VITA_DECODE_MEM_BLOCK_SIZE_ALIGN);
    mb = sceKernelAllocMemBlock(VITA_DECODE_MEM_BLOCK_NAME, VITA_DECODE_MEM_BLOCK_TYPE, p->size, arg);
    if (mb < 0)
        goto fail;

    if (sceKernelGetMemBlockBase(mb, &ptr) != 0)
        goto fail;

    *out_mb = mb;
    *out_ptr = ptr;
    return true;

fail:
    if (mb >= 0)
        sceKernelFreeMemBlock(mb);
    return false;
}

static void do_mem_free(VitaDecodeBufferFreeParams *p)
{
    sceKernelFreeMemBlock(*p->mb);
}

static bool do_unmap_open(VitaDecodeBufferAllocParams *p)
{
    void **mem_base = p->ref;
    int mb = sceCodecEngineOpenUnmapMemBlock(*mem_base, p->size);
    if (mb <= 0)
        return false;
    *p->mb = mb;
    return true;
}

static void do_unmap_close(VitaDecodeBufferFreeParams *p)
{
    sceCodecEngineCloseUnmapMemBlock(*p->mb);
}

static bool do_vaddr_alloc(VitaDecodeBufferAllocParams *p)
{
    SceUID *unmap = p->ref;
    SceUIntVAddr *vaddr = p->ptr;
    SceUIntVAddr ret = sceCodecEngineAllocMemoryFromUnmapMemBlock(*unmap, p->size, p->alignment);
    if (!ret)
        return false;
    *vaddr = ret;
    p->ptr = NULL;  // don't export it as void pointer
    return true;
}

static void do_vaddr_free(VitaDecodeBufferFreeParams *p)
{
    SceUID *unmap = p->ref;
    SceUIntVAddr *vaddr = p->ptr;
    sceCodecEngineFreeMemoryFromUnmapMemBlock(*unmap, *vaddr);
}

static VitaDecodeContextImpl *get_ctx_impl(AVCodecContext *avctx)
{
    return &((VitaDecodeContext*) avctx->priv_data)->impl;
}

static void do_uninit_decoder(AVCodecContext *avctx)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);
    if (ctx->flags & VITA_DECODE_VIDEO_FLAG_DONE_DECODER) {
        ctx->flags &= ~VITA_DECODE_VIDEO_FLAG_DONE_DECODER;
        sceAvcdecDeleteDecoder(&ctx->decoder_ctrl);
        memset(&ctx->decoder_ctrl, 0, sizeof(SceAvcdecCtrl));
    }
    if (ctx->flags & VITA_DECODE_VIDEO_FLAG_DONE_AVC_LIB) {
        ctx->flags &= ~VITA_DECODE_VIDEO_FLAG_DONE_AVC_LIB;
        sceVideodecTermLibrary(SCE_VIDEODEC_TYPE_HW_AVCDEC);
    }
    buffers_free(avctx);
    ctx->flags &= ~VITA_DECODE_VIDEO_FLAG_DECODER_READY;
}

static void do_cleanup(AVCodecContext *avctx)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);
    do_uninit_decoder(avctx);
    memset(ctx, 0, sizeof(VitaDecodeContextImpl));
}

static void extract_buffer_field_ptrs(const VitaDecodeBufferDescriptor *bd, void *ctx, SceUID **mb, void **ptr, void **ref)
{
    if (bd->offset_mb)
        *mb = (SceUID*) ((uint8_t*) ctx + bd->offset_mb);
    if (bd->offset_ptr)
        *ptr = (void*) ((uint8_t*) ctx + bd->offset_ptr);
    if (bd->offset_ref)
        *ref = (void*) ((uint8_t*) ctx + bd->offset_ref);
}

static bool buffers_alloc(AVCodecContext *avctx, int *sizes, void **ptrs)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);
    for (int i = 0; i < VITA_DECODE_BUFFER_TYPE_NB; i++) {
        const VitaDecodeBufferDescriptor *bd = &vita_decode_buffer_descriptors[i];
        SceUID dummy_out_mb = 0;
        void *dummy_out_ptr = NULL;
        VitaDecodeBufferAllocParams p = {0};
        extract_buffer_field_ptrs(bd, ctx, &p.mb, &p.ptr, &p.ref);
        p.alignment = bd->alignment_addr;
        p.size = bd->alignment_size ? FFALIGN(sizes[i], bd->alignment_size) : sizes[i];
        if (p.size <= 0) {
            av_log(avctx, AV_LOG_ERROR, "vita_h264 init: invalid specified size for %s buffer\n", bd->name);
            return false;
        }

        // allocator functions don't need null check when exporting results
        if (!p.mb)
            p.mb = &dummy_out_mb;
        if (!p.ptr)
            p.ptr = &dummy_out_ptr;

        if (!bd->alloc(&p)) {
            av_log(avctx, AV_LOG_ERROR, "vita_h264 init: allocate %s buffer failed\n", bd->name);
            return false;
        }

        sizes[i] = p.size;
        ptrs[i] = p.ptr ? *((void**) p.ptr) : NULL;
        ctx->flags |= bd->field_bit;
    }
    return true;
}

static void buffers_free(AVCodecContext *avctx)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);
    for (int i = VITA_DECODE_BUFFER_TYPE_NB - 1; i >= 0; i--) {
        const VitaDecodeBufferDescriptor *bd = &vita_decode_buffer_descriptors[i];
        if (ctx->flags & bd->field_bit) {
            VitaDecodeBufferFreeParams p = {0};
            extract_buffer_field_ptrs(bd, ctx, &p.mb, &p.ptr, &p.ref);
            bd->free(&p);
        }
    }
}

static const VitaDecodeFormatDescriptor* get_format_descriptor(enum AVPixelFormat fmt)
{
    for (int i = 0; i < FF_ARRAY_ELEMS(vita_decode_format_descriptors); i++) {
        const VitaDecodeFormatDescriptor *desc = &vita_decode_format_descriptors[i];
        if (desc->ff_format == fmt)
            return desc;
    }
    return NULL;
}

static enum AVPixelFormat resolve_user_request_format(enum AVPixelFormat fmt)
{
    const AVPixFmtDescriptor *ff_desc = NULL;
    const VitaDecodeFormatDescriptor *vita_desc = get_format_descriptor(fmt);
    if (vita_desc)
        return vita_desc->ff_format;

    ff_desc = av_pix_fmt_desc_get(fmt);
    if (!ff_desc || ff_desc->log2_chroma_w || (ff_desc->flags & AV_PIX_FMT_FLAG_PLANAR))
        return AV_PIX_FMT_YUV420P;
    else
        return AV_PIX_FMT_RGBA;
}

static const SPS* find_actived_h264_sps(AVCodecContext *avctx, H264ParamSets *ps)
{
    const SPS *sps = NULL;
    for (int i = 0; i < MAX_SPS_COUNT; i++) {
        AVBufferRef *ref = ps->sps_list[i];
        const SPS *it = ref ? (const SPS*) ref->data : NULL;
        if (!it)
            continue;

        if (sps) {
            // most h264 streams just have one SPS / PPS
            av_log(avctx, AV_LOG_WARNING, "vita_h264 parse: multiple SPS NALs\n");
            break;
        } else {
            sps = it;
        }
    }
    return sps;
}

static bool do_update_dimension(AVCodecContext *avctx, H264ParamSets *ps)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);
    const SPS *sps = find_actived_h264_sps(avctx, ps);
    const VitaDecodeFormatDescriptor *desc = get_format_descriptor(avctx->pix_fmt);
    if (!sps || !desc)
        return false;

    avctx->coded_width = 16 * sps->mb_width;
    avctx->coded_height = 16 * sps->mb_height;
    avctx->width = avctx->coded_width - (sps->crop_left + sps->crop_right);
    avctx->height = avctx->coded_height - (sps->crop_top + sps->crop_bottom);

    if (ctx->h264_width == avctx->width 
        && ctx->h264_height == avctx->height
        && ctx->h264_ref_frames == sps->ref_frame_count
        && ctx->frame_format == desc)
        return false;

    ctx->h264_width = avctx->width;
    ctx->h264_height = avctx->height;
    ctx->h264_ref_frames = sps->ref_frame_count;

    // https://github.com/MakiseKurisu/vita-sceVideodecInitLibrary-test
    ctx->frame_width = FFMAX(FFALIGN(avctx->width, 16), 64);
    ctx->frame_height = FFMAX(FFALIGN(avctx->height, 16), 64);
    ctx->frame_pitch = FFALIGN(avctx->width, desc->pitch_alignment);
    ctx->frame_format = desc;
    return true;
}

static bool do_parse_meta_data_raw(AVCodecContext *avctx, uint8_t *buf, int size, bool need_resize)
{
    int ret = 0;
    bool succeed = false;
    bool changed = false;
    int h264_is_avcc = 0;
    int h264_len_bytes = 0;
    H264ParamSets ps = {0};

    ret = ff_h264_decode_extradata(buf, size,
        &ps, &h264_is_avcc, &h264_len_bytes,
        avctx->err_recognition, avctx);
    if (ret < 0)
        goto bail;

    changed = do_update_dimension(avctx, &ps);
    if (changed && need_resize)
        do_init(avctx);

    succeed = true;

bail:
    ff_h264_ps_uninit(&ps);
    return succeed;
}

static bool do_skip_nal_start_code(const uint8_t **p, const uint8_t *end)
{
    uint32_t state = 0;
    const uint8_t *skip = avpriv_find_start_code(*p, end, &state);
    if (skip >= end)
        return false;

    *p = skip - 1;
    return true;
}

static bool do_find_meta_nals(const uint8_t **buf, int *size)
{
    bool has_pps = false;
    bool has_sps = false;
    const uint8_t *p = *buf;
    const uint8_t *end = p + *size;
    const uint8_t *nal_end = NULL;

    if (!do_skip_nal_start_code(&p, end))
        return false;

    while (p < end) {
        switch (*p & 0x1f) {
        case H264_NAL_PPS:
            has_pps = true;
            break;
        case H264_NAL_SPS:
            has_sps = true;
            break;

        case H264_NAL_SLICE:
        case H264_NAL_DPA:
        case H264_NAL_DPB:
        case H264_NAL_DPC:
        case H264_NAL_IDR_SLICE:
            // non-VCL NALs will not follow VCL NALs in an access unit
            return false;
        }

        if (do_skip_nal_start_code(&p, end)) {
            // even though start code may be 0x0001
            // NAL parsing should be fine with extra trailing zero bytes
            nal_end = p - 3;
        } else {
            p = end;
            nal_end = end;
        }

        if (has_pps && has_sps) {
            *size = nal_end - *buf;
            return true;
        }
    }

    return false;
}

static bool do_parse_meta_nals(AVCodecContext *avctx, H264ParamSets *ps, const uint8_t *buf, int size)
{
    int ret = 0;
    bool succeed = false;
    H2645Packet nals = {0};

    ret = ff_h2645_packet_split(&nals, buf, size, avctx, 0, 0, AV_CODEC_ID_H264, 0, 0);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 parse: split NALs failed\n");
        goto fail;
    }

    for (int i = 0; i < nals.nb_nals; i++) {
        H2645NAL *nal = &nals.nals[i];
        switch (nal->type) {
        case H264_NAL_PPS:
            ret = ff_h264_decode_picture_parameter_set(&nal->gb, avctx, ps, nal->size_bits);
            if (ret < 0) {
                av_log(avctx, AV_LOG_ERROR, "vita_h264 parse: parse PPS failed\n");
                goto fail;
            }
            break;
        case H264_NAL_SPS:
            ret = ff_h264_decode_seq_parameter_set(&nal->gb, avctx, ps, 0);
            if (ret < 0) {
                av_log(avctx, AV_LOG_ERROR, "vita_h264 parse: parse SPS failed\n");
                goto fail;
            }
            break;
        }
    }
    succeed = true;
fail:
    ff_h2645_packet_uninit(&nals);
    return succeed;
}

static void do_parse_meta_data_probed(AVCodecContext *avctx, AVPacket *avpkt)
{
    int size = avpkt->size;
    const uint8_t *buf = avpkt->data;
    H264ParamSets ps = {0};

    if (!do_find_meta_nals(&buf, &size))
        goto bail;
    if (!do_parse_meta_nals(avctx, &ps, buf, size))
        goto bail;
    if (!do_update_dimension(avctx, &ps))
        goto bail;

    do_init(avctx);
bail:
    ff_h264_ps_uninit(&ps);
}

static void do_init(AVCodecContext *avctx)
{
    int ret = 0;
    int ouput_buf_size = 0;
    int codec_buf_size = 0;

    SceVideodecCtrl ctrl = {0};
    SceAvcdecDecoderInfo di = {0};
    SceVideodecQueryInitInfo init = {0};
    SceAvcdecQueryDecoderInfo qdi = {0};
    int sizes[VITA_DECODE_BUFFER_TYPE_NB] = {0};
    void *ptrs[VITA_DECODE_BUFFER_TYPE_NB] = {NULL};
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);

    if (ctx->h264_width <= 0 || ctx->h264_height <= 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: unknown video width or height\n");
        goto fail;
    }

    // the decoder may have been initialized before
    do_uninit_decoder(avctx);

    init.hwAvc.size = sizeof(SceVideodecQueryInitInfoHwAvcdec);
    init.hwAvc.horizontal = ctx->frame_width;
    init.hwAvc.vertical = ctx->frame_height;
    init.hwAvc.numOfRefFrames = ctx->h264_ref_frames;
    init.hwAvc.numOfStreams = 1;
    sceVideodecSetConfigInternal(SCE_VIDEODEC_TYPE_HW_AVCDEC, 2);
    sceAvcdecSetDecodeMode(SCE_VIDEODEC_TYPE_HW_AVCDEC, 0x80);
    sceVideodecQueryMemSizeInternal(SCE_VIDEODEC_TYPE_HW_AVCDEC, &init, &codec_buf_size);
    if (codec_buf_size <= 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: query codec buffer size failed\n");
        goto fail;
    }

    qdi.horizontal = init.hwAvc.horizontal;
    qdi.vertical = init.hwAvc.vertical;
    qdi.numOfRefFrames = init.hwAvc.numOfRefFrames;
    ret = sceAvcdecQueryDecoderMemSizeInternal(SCE_VIDEODEC_TYPE_HW_AVCDEC, &qdi, &di);
    if (ret != 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: query frame buffer size failed 0x%x\n", ret);
        goto fail;
    }

    ouput_buf_size = av_image_get_buffer_size(avctx->pix_fmt, ctx->frame_width, ctx->frame_height, 1);
    if (ouput_buf_size <= 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: invalid output buffer size\n");
        goto fail;
    }

    sizes[VITA_DECODE_BUFFER_TYPE_FRAME] = di.frameMemSize;
    sizes[VITA_DECODE_BUFFER_TYPE_OUTPUT] = ouput_buf_size;
    sizes[VITA_DECODE_BUFFER_TYPE_CODEC_MEM] = codec_buf_size;
    sizes[VITA_DECODE_BUFFER_TYPE_CODEC_UNMAP] = codec_buf_size;
    sizes[VITA_DECODE_BUFFER_TYPE_CODEC_VADDR] = codec_buf_size;
    if (!buffers_alloc(avctx, sizes, ptrs))
        goto fail;

    ctrl.vaddr = ctx->decoder_vaddr_codec;
    ctrl.size = codec_buf_size;
    ret = sceVideodecInitLibraryWithUnmapMemInternal(SCE_VIDEODEC_TYPE_HW_AVCDEC, &ctrl, &init);
    if (ret != 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: init library failed 0x%x\n", ret);
        goto fail;
    }
    ctx->flags |= VITA_DECODE_VIDEO_FLAG_DONE_AVC_LIB;

    ctx->decoder_ctrl.frameBuf.pBuf = ptrs[VITA_DECODE_BUFFER_TYPE_FRAME];
    ctx->decoder_ctrl.frameBuf.size = sizes[VITA_DECODE_BUFFER_TYPE_FRAME];
    ret = sceAvcdecCreateDecoderInternal(SCE_VIDEODEC_TYPE_HW_AVCDEC, &ctx->decoder_ctrl, &qdi);
    if (ret != 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: create decoder failed: 0x%x\n", ret);
        goto fail;
    }
    ctx->flags |= VITA_DECODE_VIDEO_FLAG_DONE_DECODER;

    ctx->flags |= VITA_DECODE_VIDEO_FLAG_DECODER_READY;
    return;

fail:
    do_cleanup(avctx);
}

static av_cold int vita_init(AVCodecContext *avctx)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);
    memset(ctx, 0, sizeof(VitaDecodeContextImpl));
    avctx->pix_fmt = resolve_user_request_format(avctx->pix_fmt);
    ctx->flags |= VITA_DECODE_VIDEO_FLAG_INIT_POSTPONED;
    do_parse_meta_data_raw(avctx, avctx->extradata, avctx->extradata_size, false);
    return 0;
}

static av_cold int vita_close(AVCodecContext *avctx)
{
    do_cleanup(avctx);
    return 0;
}

static void vita_flush(AVCodecContext *avctx)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);
    if (!(ctx->flags & VITA_DECODE_VIDEO_FLAG_DECODER_READY))
        return;

    sceAvcdecDecodeFlush(&ctx->decoder_ctrl);
}

static AVRational* select_time_base(AVCodecContext *avctx)
{
    AVRational *base = &avctx->pkt_timebase;
    return (base && base->num && base->den) ? base : NULL;
}

static void to_timestamp_vita(int64_t pts, AVRational *ff_base, SceVideodecTimeStamp *ts)
{
    int64_t result = 0;
    if (pts == AV_NOPTS_VALUE) {
        ts->upper = VITA_DECODE_TIMESTAMP_VOID;
        ts->lower = VITA_DECODE_TIMESTAMP_VOID;
        return;
    }

    if (ff_base) {
        AVRational vita_base = av_make_q(1, VITA_DECODE_TIMESTAMP_UNIT_BASE);
        result = av_rescale_q(pts, *ff_base, vita_base);
    } else {
        result = pts;
    }
    ts->upper = (SceUInt32) (result >> 32);
    ts->lower = (SceUInt32) (result);
}

static int64_t to_timestamp_ff(AVRational *ff_base, SceVideodecTimeStamp *ts)
{
    int64_t count = 0;
    if (ts->upper == VITA_DECODE_TIMESTAMP_VOID && ts->lower == VITA_DECODE_TIMESTAMP_VOID)
        return AV_NOPTS_VALUE;

    count = (((uint64_t) ts->upper) << 32) | ((uint64_t) ts->lower);
    if (ff_base) {
        AVRational vita_base = av_make_q(1, VITA_DECODE_TIMESTAMP_UNIT_BASE);
        return av_rescale_q(count, vita_base, *ff_base);
    } else {
        return count;
    }
}

static bool do_output_frame(AVCodecContext *avctx, AVFrame *frame, SceAvcdecPicture *p)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);

    int ret = 0;
    int max_steps[4] = {0};
    int ls_list[4] = {0};
    uint8_t *src_list[4] = {0};
    uint32_t crop_x = 0;
    uint32_t crop_y = 0;
    uint8_t *pixels = NULL;
    AVRational *time_base = select_time_base(avctx);
    const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get(avctx->pix_fmt);
    if (!desc)
        return false;

    av_image_fill_max_pixsteps(max_steps, NULL, desc);
    crop_x = FFMIN(p->frame.frameCropLeftOffset, p->frame.framePitch - ctx->h264_width);
    crop_y = FFMIN(p->frame.frameCropTopOffset, p->frame.frameHeight - ctx->h264_height);
    pixels = (uint8_t*) ctx->decoder_ptr_output + (crop_x + crop_y * p->frame.framePitch) * max_steps[0];

    ret = av_image_fill_arrays(src_list, ls_list,
        pixels, avctx->pix_fmt, 
        p->frame.framePitch, p->frame.frameHeight, 1);
    if (ret <= 0)
        return false;

    av_image_copy(frame->data, frame->linesize, 
        (const uint8_t**) src_list, (const int*) ls_list,
        avctx->pix_fmt, avctx->width, avctx->height);

    frame->pts = to_timestamp_ff(time_base, &p->info.pts);
    return true;
}

static int vita_decode(AVCodecContext *avctx, AVFrame *frame, int *got_frame, AVPacket *avpkt)
{
    int ret = 0;
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);

    SceAvcdecPicture p = {0};
    SceAvcdecPicture *pp[] = {&p};
    SceAvcdecArrayPicture ap = {0};

    // is it a corner use case?
    // some developers may send SPS and PPS through side data,
    // but a more proper way may be sending them through packet.
    size_t side_data_size = 0;
    uint8_t *side_data_buf = av_packet_get_side_data(avpkt, AV_PKT_DATA_NEW_EXTRADATA, &side_data_size);
    if (side_data_buf)
        do_parse_meta_data_raw(avctx, side_data_buf, side_data_size, true);

    // it's necessary to probe SPS or PPS for every packet
    // 1. there is no extradata being passed when decoding a raw h264 stream with a parser
    // 2. the new SPS or PPS only appears in packet when decoding a mixed h264 stream
    //    containing different-sized video data
    do_parse_meta_data_probed(avctx, avpkt);

    if (ctx->flags & VITA_DECODE_VIDEO_FLAG_INIT_POSTPONED) {
        ctx->flags &= ~VITA_DECODE_VIDEO_FLAG_INIT_POSTPONED;
        do_init(avctx);
    }

    // reject any decode invocations if init failed
    if (!(ctx->flags & VITA_DECODE_VIDEO_FLAG_DECODER_READY)) {
        return AVERROR_UNKNOWN;
    }

    p.size = sizeof(SceAvcdecPicture);
    p.frame.pixelType = ctx->frame_format->sce_format;
    p.frame.framePitch = ctx->frame_pitch;
    p.frame.frameWidth = ctx->frame_width;
    p.frame.frameHeight = ctx->frame_height;
    p.frame.pPicture[0] = ctx->decoder_ptr_output;

    ap.numOfElm = 1;
    ap.pPicture = pp;

    if (!avpkt->size) {
        ret = sceAvcdecDecodeStop(&ctx->decoder_ctrl, &ap);
        if (ret < 0) {
            av_log(avctx, AV_LOG_ERROR, "vita_h264 decode: flush failed 0x%x\n", ret);
            return AVERROR_UNKNOWN;
        }
    } else {
        SceAvcdecAu au = {0};
        SceAvcdecArrayPicture wap = {0};
        AVRational *time_base = select_time_base(avctx);
        au.es.pBuf = avpkt->data;
        au.es.size = avpkt->size;
        to_timestamp_vita(avpkt->pts, time_base,  &au.pts);
        to_timestamp_vita(avpkt->dts, time_base, &au.dts);

        ret = sceAvcdecDecodeAuInternal(&ctx->decoder_ctrl, &au, &ctx->decoder_picture_int);
        if (ret < 0) {
            av_log(avctx, AV_LOG_ERROR, "vita_h264 decode: decode au failed 0x%x\n", ret);
            return AVERROR_UNKNOWN;
        }

        ret = sceAvcdecDecodeGetPictureWithWorkPictureInternal(&ctx->decoder_ctrl, &ap, &wap, &ctx->decoder_picture_int);
        if (ret < 0) {
            av_log(avctx, AV_LOG_ERROR, "vita_h264 decode: decode work picture failed 0x%x\n", ret);
            return AVERROR_UNKNOWN;
        }
    }

    if (ap.numOfOutput) {
        ret = ff_get_buffer(avctx, frame, 0);
        if (ret < 0)
            return ret;

        if (do_output_frame(avctx, frame, &p)) {
            *got_frame = 1;
        } else {
            av_frame_unref(frame);
            av_log(avctx, AV_LOG_ERROR, "vita_h264 decode: output frame failed\n");
        }
    }

    // the decoder has consumed the all data input
    return 0;
}

static const AVClass vita_h264_dec_class = {
    .class_name     = "vita_h264_dec",
    .item_name      = av_default_item_name,
    .version        = LIBAVUTIL_VERSION_INT,
};

const FFCodec ff_h264_vita_decoder = {
    .p.name             = "h264_vita",
    CODEC_LONG_NAME("h264 (vita)"),
    .p.type             = AVMEDIA_TYPE_VIDEO,
    .p.id               = AV_CODEC_ID_H264,
    .priv_data_size     = sizeof(VitaDecodeContext),
    .init               = vita_init,
    .close              = vita_close,
    .flush              = vita_flush,
    FF_CODEC_DECODE_CB(vita_decode),
    .bsfs               = "h264_mp4toannexb",
    .p.priv_class       = &vita_h264_dec_class,
    .p.capabilities     = AV_CODEC_CAP_DR1 | AV_CODEC_CAP_DELAY | AV_CODEC_CAP_AVOID_PROBING | AV_CODEC_CAP_HARDWARE,
    .caps_internal      = FF_CODEC_CAP_NOT_INIT_THREADSAFE | FF_CODEC_CAP_INIT_CLEANUP,
    .p.wrapper_name     = "vita",
};
