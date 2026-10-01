package com.offlinewallet.ui.views

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import com.offlinewallet.models.BlockchainNode
import com.offlinewallet.models.BlockchainNodeType
import java.util.*

/**
 * BlockchainGraphView - Directed Acyclic Graph (DAG) Layout
 * Visualizes the wallet's hash chain from Genesis to latest transaction.
 */
class BlockchainGraphView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null, defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val nodePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val nodeStrokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 4f
        color = Color.WHITE
    }
    private val linkPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        strokeWidth = 6f
        color = Color.parseColor("#444D66")
        style = Paint.Style.STROKE
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.WHITE
        textSize = 24f
        textAlign = Paint.Align.CENTER
        typeface = Typeface.DEFAULT_BOLD
    }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#8E94A3")
        textSize = 20f
        textAlign = Paint.Align.CENTER
    }

    private var nodes: List<BlockchainNode> = emptyList()
    private val nodePoints = mutableMapOf<Int, PointF>()
    
    private val nodeRadius = 50f
    private val horizontalStep = 200f
    private val verticalStep = 180f
    
    var onNodeSelected: ((BlockchainNode) -> Unit)? = null

    fun setNodes(newNodes: List<BlockchainNode>) {
        // Sort chronologically (Genesis first)
        this.nodes = newNodes.sortedBy { it.counter }
        requestLayout()
        invalidate()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = MeasureSpec.getSize(widthMeasureSpec)
        val calculatedHeight = if (nodes.isEmpty()) 400 else (nodes.size * verticalStep + 200f).toInt()
        setMeasuredDimension(width, calculatedHeight)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (nodes.isEmpty()) {
            textPaint.textSize = 32f
            canvas.drawText("Empty Ledger", width / 2f, 200f, textPaint)
            return
        }

        nodePoints.clear()
        val centerX = width / 2f
        var currentY = 100f

        // 1. Calculate Node Positions (Staggered Layout)
        nodes.forEachIndexed { i, _ ->
            // Shift x-position slightly for visual "graph" effect
            val offsetX = if (i % 2 == 0) -80f else 80f
            val x = centerX + offsetX
            val y = currentY + i * verticalStep
            nodePoints[i] = PointF(x, y)
        }

        // 2. Draw Links (Edges) based on PrevHash linkage
        linkPaint.pathEffect = null
        nodes.forEachIndexed { i, node ->
            val endPoint = nodePoints[i]!!
            
            // Find the parent node (where parent.hash == node.prevHash)
            val parentIndex = nodes.indexOfFirst { it.hash == node.prevHash }
            if (parentIndex != -1) {
                val startPoint = nodePoints[parentIndex]!!
                
                val path = Path()
                path.moveTo(startPoint.x, startPoint.y)
                
                // Curve towards center then to the node
                val midY = (startPoint.y + endPoint.y) / 2
                path.quadTo(centerX, midY, endPoint.x, endPoint.y)
                canvas.drawPath(path, linkPaint)
                
                drawArrowHead(canvas, endPoint.x, endPoint.y, startPoint.x, startPoint.y)
            } else if (node.type != BlockchainNodeType.GENESIS) {
                // If it's not genesis and we can't find the parent, link to the previous one in list as fallback
                if (i > 0) {
                    val startPoint = nodePoints[i - 1]!!
                    val path = Path()
                    path.moveTo(startPoint.x, startPoint.y)
                    val midY = (startPoint.y + endPoint.y) / 2
                    path.quadTo(centerX, midY, endPoint.x, endPoint.y)
                    canvas.drawPath(path, linkPaint)
                    drawArrowHead(canvas, endPoint.x, endPoint.y, startPoint.x, startPoint.y)
                }
            }
        }

        // 3. Draw Nodes
        nodes.forEachIndexed { i, node ->
            val point = nodePoints[i]!!
            
            // Node Color & Style based on Security Status
            val color = when(node.type) {
                BlockchainNodeType.GENESIS -> "#3F51B5" // indigo
                BlockchainNodeType.TOPUP -> "#FFC107" // amber
                BlockchainNodeType.PAYMENT_SENT -> "#F44336" // red
                BlockchainNodeType.PAYMENT_RECEIVED -> "#4CAF50" // green
            }
            
            nodePaint.color = Color.parseColor(color)
            canvas.drawCircle(point.x, point.y, nodeRadius, nodePaint)
            
            // Security Role Indicator (Root / Checkpoint)
            when (node.status) {
                "ROOT" -> {
                    nodeStrokePaint.color = Color.CYAN
                    nodeStrokePaint.strokeWidth = 8f
                    canvas.drawCircle(point.x, point.y, nodeRadius + 5, nodeStrokePaint) // Double border
                    nodeStrokePaint.strokeWidth = 4f
                }
                "CHECKPOINT" -> {
                    nodeStrokePaint.color = Color.parseColor("#9C27B0") // Purple
                    nodeStrokePaint.strokeWidth = 8f
                    canvas.drawCircle(point.x, point.y, nodeRadius, nodeStrokePaint)
                    nodeStrokePaint.strokeWidth = 4f
                }
                "SETTLED" -> {
                    nodeStrokePaint.color = Color.WHITE
                    nodeStrokePaint.strokeWidth = 4f
                    canvas.drawCircle(point.x, point.y, nodeRadius, nodeStrokePaint)
                }
                "LOCAL" -> {
                    nodeStrokePaint.color = Color.parseColor("#FFC107") // Warning Yellow
                    nodeStrokePaint.strokeWidth = 6f
                    canvas.drawCircle(point.x, point.y, nodeRadius, nodeStrokePaint)
                }
                else -> {
                    nodeStrokePaint.color = Color.WHITE
                    canvas.drawCircle(point.x, point.y, nodeRadius, nodeStrokePaint)
                }
            }
            
            // Type Initial
            textPaint.textSize = 30f
            val char = if (node.status == "ROOT") "⚓" else node.type.name.take(1)
            canvas.drawText(char, point.x, point.y + 10f, textPaint)
            
            // Labels
            labelPaint.color = Color.parseColor("#8E94A3")
            val labelSuffix = if (node.status == "ROOT") " (ROOT)" else if (node.status == "CHECKPOINT") " (ANCHOR)" else ""
            canvas.drawText("#${node.counter}$labelSuffix", point.x, point.y + nodeRadius + 30f, labelPaint)
            
            if (node.type != BlockchainNodeType.GENESIS) {
                labelPaint.color = Color.WHITE
                val prefix = if (node.type == BlockchainNodeType.PAYMENT_SENT) "-" else "+"
                val amountStr = "${prefix}₹${node.amountP / 100.0}"
                // Draw amount label to the side
                val sideX = if (point.x < centerX) point.x - nodeRadius - 60f else point.x + nodeRadius + 60f
                canvas.drawText(amountStr, sideX, point.y + 10f, labelPaint)
            }
        }
    }

    private fun drawArrowHead(canvas: Canvas, x: Float, y: Float, fromX: Float, fromY: Float) {
        val angle = Math.atan2((y - fromY).toDouble(), (x - fromX).toDouble())
        val headLen = 20f
        val path = Path()
        path.moveTo(x, y)
        path.lineTo(
            (x - headLen * Math.cos(angle - Math.PI / 6)).toFloat(),
            (y - headLen * Math.sin(angle - Math.PI / 6)).toFloat()
        )
        path.moveTo(x, y)
        path.lineTo(
            (x - headLen * Math.cos(angle + Math.PI / 6)).toFloat(),
            (y - headLen * Math.sin(angle + Math.PI / 6)).toFloat()
        )
        canvas.drawPath(path, nodeStrokePaint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (event.action == MotionEvent.ACTION_DOWN) {
            val x = event.x
            val y = event.y
            
            nodePoints.forEach { (index, point) ->
                val dist = Math.sqrt(((x - point.x) * (x - point.x) + (y - point.y) * (y - point.y)).toDouble())
                if (dist <= nodeRadius + 20) {
                    onNodeSelected?.invoke(nodes[index])
                    return true
                }
            }
        }
        return super.onTouchEvent(event)
    }

    private fun Double.pow(n: Int): Double = Math.pow(this, n.toDouble())
}
