'use strict'

// webglextensiondirectoryguard.js —— WebGL 扩展与指纹面目录。
//
// 威胁模型：
//   WebGL 扩展与调试/计时接口放大显卡指纹识别面，调试与读回类扩展风险更高，核心渲染扩展常规。
//   纯字符查表，不用正则。

const WGE_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WGE_BLOCK = Object.freeze([
  'WEBGL_debug_renderer_info',
  'WEBGL_debug_shaders',
  'EXT_disjoint_timer_query',
  'EXT_disjoint_timer_query_webgl2',
  'EXT_disjoint_timer_query_webgl1',
])

const WGE_WARN = Object.freeze([
  'WEBGL_lose_context',
  'WEBGL_draw_buffers',
  'WEBGL_depth_texture',
  'WEBGL_compressed_texture_s3tc',
  'WEBGL_compressed_texture_s3tc_srgb',
  'WEBGL_compressed_texture_pvrtc',
  'WEBGL_compressed_texture_etc1',
  'WEBGL_compressed_texture_astc',
  'WEBGL_compressed_texture_bptc',
  'WEBGL_compressed_texture_etc',
  'EXT_texture_compression_bptc',
  'EXT_texture_compression_rgtc',
  'EXT_texture_filter_anisotropic',
  'EXT_color_buffer_float',
  'EXT_color_buffer_half_float',
  'EXT_float_blend',
  'EXT_shader_texture_lod',
  'EXT_sRGB',
  'EXT_blend_minmax',
  'EXT_frag_depth',
  'EXT_sRGB_write_control',
  'EXT_texture_norm16',
  'EXT_clip_cull_distance',
  'EXT_occlusion_query_boolean',
  'EXT_polygon_offset_clamp',
  'EXT_render_snorm',
  'EXT_texture_mirror_clamp_to_edge',
  'EXT_primitive_bounding_box',
  'OES_texture_float',
  'OES_texture_half_float',
  'OES_texture_float_linear',
  'OES_texture_half_float_linear',
  'OES_standard_derivatives',
  'OES_vertex_array_object',
  'OES_element_index_uint',
  'OES_geometry_shader',
  'OES_sample_variables',
  'OES_shader_multisample_interpolation',
  'OES_shader_image_atomic',
  'OES_draw_buffers_indexed',
  'OES_fbo_render_mipmap',
  'OES_single_pass_cube_map',
  'OES_single_pass_cube_map_ext',
  'KHR_parallel_shader_compile',
  'WEBGL_multi_draw',
  'WEBGL_clip_cull_distance',
  'WEBGL_polygon_mode',
  'WEBGL_provoking_vertex',
  'WEBGL_render_shared',
  'WEBGL_stencil_texturing',
  'WEBGL_shader_pixel_local_storage',
])

const WGE_ALLOW = Object.freeze([
  'ANGLE_instanced_arrays',
  'WEBGL_color_buffer_float',
  'WEBGL_color_buffer_half_float',
])

function WGELower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WGEIn (list, v) {
  for (const x of list) { if (WGELower(x) === v) return true }
  return false
}

function WGEClassify (tok) {
  const v = WGELower(String(tok == null ? '' : tok).trim())
  if (WGEIn(WGE_BLOCK, v)) return WGE_CLASS.BLOCK
  if (WGEIn(WGE_WARN, v)) return WGE_CLASS.WARN
  if (WGEIn(WGE_ALLOW, v)) return WGE_CLASS.ALLOW
  return WGE_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WGE_CLASS: WGE_CLASS,
  WGE_BLOCK: WGE_BLOCK,
  WGE_WARN: WGE_WARN,
  WGE_ALLOW: WGE_ALLOW,
  WGEClassify: WGEClassify
})
