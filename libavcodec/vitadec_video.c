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

// non-exported internal API
SceInt32 sceAvcdecDecodeFlush(SceAvcdecCtrl *ctrl);
SceInt32 sceAvcdecDecodeStop(SceAvcdecCtrl *ctrl, SceAvcdecArrayPicture *pictures);

#define VITA_DECODE_VIDEO_FLAG_INIT_POSTPONED       1
#define VITA_DECODE_VIDEO_FLAG_DECODER_READY        (1 << 1)
#define VITA_DECODE_VIDEO_FLAG_DONE_AVC_LIB         (1 << 2)
#define VITA_DECODE_VIDEO_FLAG_DONE_DECODER         (1 << 3)
#define VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_DECODE   (1 << 4)
#define VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_OUTPUT   (1 << 5)

typedef struct VitaDecodeFormatDescriptor {
    enum AVPixelFormat ff_format;
    SceAvcdecPixelFormat sce_format;
    int pitch_alignment;
} VitaDecodeFormatDescriptor;

typedef struct VitaDecodeContextImpl {
    int flags;

    int frame_width;
    int frame_height;
    int frame_pitch;
    const VitaDecodeFormatDescriptor *frame_format;

    SceUID decoder_mb_frame;
    SceUID decoder_mb_output;
    void *decoder_ptr_output;
    SceAvcdecCtrl decoder_ctrl;

    int h264_width;
    int h264_height;
    int h264_ref_frames;
} VitaDecodeContextImpl;

typedef struct VitaDecodeContext {
    AVClass *clz;
    VitaDecodeContextImpl impl;
} VitaDecodeContext;

#define VITA_MEM_BLOCK_NAME             "ffmpeg_vdec"
#define VITA_MEM_BLOCK_TYPE             SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW
#define VITA_MEM_BLOCK_SIZE_ALIGN       (256 * 1024)

#define VITA_DECODE_BUFF_ADDR_ALIGN     (1024 * 1024)
#define VITA_VOID_TIMESTAMP             (0xffffffff)

static const VitaDecodeFormatDescriptor vita_decode_format_descriptors[] = {
    { AV_PIX_FMT_RGBA, SCE_AVCDEC_PIXELFORMAT_RGBA8888, 16 },
    { AV_PIX_FMT_BGR565LE, SCE_AVCDEC_PIXELFORMAT_RGBA565, 16 },
    { AV_PIX_FMT_BGR555LE, SCE_AVCDEC_PIXELFORMAT_RGBA5551, 16 },
    { AV_PIX_FMT_YUV420P, SCE_AVCDEC_PIXELFORMAT_YUV420_RASTER, 32 },
    { AV_PIX_FMT_NV12, SCE_AVCDEC_PIXELFORMAT_YUV420_PACKED_RASTER, 16 },
};

static void do_init(AVCodecContext *avctx);

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
    if (ctx->flags & VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_DECODE) {
        ctx->flags &= ~VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_DECODE;
        sceKernelFreeMemBlock(ctx->decoder_mb_frame);
    }
    if (ctx->flags & VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_OUTPUT) {
        ctx->flags &= ~VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_OUTPUT;
        sceKernelFreeMemBlock(ctx->decoder_mb_output);
    }
    if (ctx->flags & VITA_DECODE_VIDEO_FLAG_DONE_AVC_LIB) {
        ctx->flags &= ~VITA_DECODE_VIDEO_FLAG_DONE_AVC_LIB;
        sceVideodecTermLibrary(SCE_VIDEODEC_TYPE_HW_AVCDEC);
    }
}

static void do_cleanup(AVCodecContext *avctx)
{
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);
    do_uninit_decoder(avctx);
    memset(ctx, 0, sizeof(VitaDecodeContextImpl));
}

static bool alloc_vram(size_t size, size_t align, SceUID *out_mb, void **out_ptr)
{
    int ret = 0;
    SceUID mb = -1;
    void *ptr = NULL;

    SceKernelAllocMemBlockOpt opt_args = {0};
    SceKernelAllocMemBlockOpt *opt = NULL;
    if (align) {
        opt = &opt_args;
        opt->size = sizeof(SceKernelAllocMemBlockOpt);
        opt->attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_ALIGNMENT;
        opt->alignment = align;
    }

    mb = sceKernelAllocMemBlock(VITA_MEM_BLOCK_NAME, VITA_MEM_BLOCK_TYPE, size, opt);
    if (mb < 0)
        goto fail;

    ret = sceKernelGetMemBlockBase(mb, &ptr);
    if (ret < 0)
        goto fail;

    *out_mb = mb;
    *out_ptr = ptr;
    return true;

fail:
    if (mb >= 0)
        sceKernelFreeMemBlock(mb);
    return false;
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
    size_t decode_buf_size = 0;
    size_t ouput_buf_size = 0;
    void *buf_decode_ptr = NULL;

    SceVideodecQueryInitInfoHwAvcdec init = {0};
    SceAvcdecDecoderInfo di = {0};
    SceAvcdecQueryDecoderInfo qdi = {0};
    VitaDecodeContextImpl *ctx = get_ctx_impl(avctx);

    if (ctx->h264_width <= 0 || ctx->h264_height <= 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: unknown video width or height\n");
        goto bail;
    }

    do_uninit_decoder(avctx);

    init.size = sizeof(SceVideodecQueryInitInfoHwAvcdec);
    init.horizontal = ctx->frame_width;
    init.vertical = ctx->frame_height;
    init.numOfRefFrames = ctx->h264_ref_frames;
    init.numOfStreams = 1;
    ret = sceVideodecInitLibrary(SCE_VIDEODEC_TYPE_HW_AVCDEC, &init);
    if (ret != 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: init library failed 0x%x\n", ret);
        goto bail;
    }
    ctx->flags |= VITA_DECODE_VIDEO_FLAG_DONE_AVC_LIB;

    qdi.horizontal = init.horizontal;
    qdi.vertical = init.vertical;
    qdi.numOfRefFrames = ctx->h264_ref_frames;
    ret = sceAvcdecQueryDecoderMemSize(SCE_VIDEODEC_TYPE_HW_AVCDEC, &qdi, &di);
    if (ret != 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: query mem size failed 0x%x\n", ret);
        goto bail;
    }


    decode_buf_size = FFALIGN(di.frameMemSize, VITA_MEM_BLOCK_SIZE_ALIGN);
    if (!alloc_vram(decode_buf_size, VITA_DECODE_BUFF_ADDR_ALIGN, &ctx->decoder_mb_frame, &buf_decode_ptr)) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: alloc decode buffer failed\n");
        goto bail;
    }
    ctx->flags |= VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_DECODE;

    ouput_buf_size = av_image_get_buffer_size(avctx->pix_fmt, ctx->frame_width, ctx->frame_height, 1);
    if (ouput_buf_size <= 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: invalid frame buffer size\n");
        goto bail;
    }

    ouput_buf_size = FFALIGN(ouput_buf_size, VITA_MEM_BLOCK_SIZE_ALIGN);
    if (!alloc_vram(ouput_buf_size, 0, &ctx->decoder_mb_output, &ctx->decoder_ptr_output)) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: alloc output buffer failed\n");
        goto bail;
    }
    ctx->flags |= VITA_DECODE_VIDEO_FLAG_DONE_BUFFER_OUTPUT;

    ctx->decoder_ctrl.frameBuf.pBuf = buf_decode_ptr;
    ctx->decoder_ctrl.frameBuf.size = decode_buf_size;
    ret = sceAvcdecCreateDecoder(SCE_VIDEODEC_TYPE_HW_AVCDEC, &ctx->decoder_ctrl, &qdi);
    if (ret != 0) {
        av_log(avctx, AV_LOG_ERROR, "vita_h264 init: create decoder failed: 0x%x\n", ret);
        goto bail;
    }
    ctx->flags |= VITA_DECODE_VIDEO_FLAG_DONE_DECODER;

    ctx->flags |= VITA_DECODE_VIDEO_FLAG_DECODER_READY;
    return;

bail:
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
        au.pts.upper = VITA_VOID_TIMESTAMP;
        au.pts.lower = VITA_VOID_TIMESTAMP;
        au.dts.upper = VITA_VOID_TIMESTAMP;
        au.dts.lower = VITA_VOID_TIMESTAMP;
        au.es.pBuf = avpkt->data;
        au.es.size = avpkt->size;

        ret = sceAvcdecDecode(&ctx->decoder_ctrl, &au, &ap);
        if (ret < 0) {
            av_log(avctx, AV_LOG_ERROR, "vita_h264 decode: decode failed 0x%x\n", ret);
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
