package net.jsign.asn1;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.encoders.Hex;

/**
 * Derived from org.bouncycastle.asn1.util.ASN1Dump
 */
public class ASN1ResolvedDump
{
    private static final String  TAB = "    ";
    private static final int SAMPLE_SIZE = 32;
    
    static final OIDResolver resolver = new OIDResolver();

    /**
     * dump a DER object as a formatted string with indentation
     *
     * @param obj the ASN1Primitive to be dumped out.
     */
    static void _dumpAsString(
        String      indent,
        boolean     verbose,
        ASN1Primitive obj,
        StringBuilder    buf)
    {
        String nl = System.getProperty("line.separator");
        if (obj instanceof ASN1Sequence)
        {
            Enumeration<?>  e = ((ASN1Sequence)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            if (obj instanceof BERSequence)
            {
                buf.append("BER Sequence");
            }
            else if (obj instanceof DERSequence)
            {
                buf.append("DER Sequence");
            }
            else
            {
                buf.append("Sequence");
            }

            buf.append(nl);

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null || o.equals(DERNull.INSTANCE))
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof ASN1Primitive)
                {
                    _dumpAsString(tab, verbose, (ASN1Primitive)o, buf);
                }
                else
                {
                    _dumpAsString(tab, verbose, ((ASN1Encodable)o).toASN1Primitive(), buf);
                }
            }
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            String          tab = indent + TAB;

            buf.append(indent);
            if (obj instanceof BERTaggedObject)
            {
                buf.append("BER Tagged [");
            }
            else
            {
                buf.append("Tagged [");
            }

            ASN1TaggedObject o = (ASN1TaggedObject)obj;

            buf.append(o.getTagNo());
            buf.append(']');

            if (!o.isExplicit())
            {
                buf.append(" IMPLICIT ");
            }

            buf.append(nl);

            _dumpAsString(tab, verbose, o.getObject(), buf);
        }
        else if (obj instanceof BERSet)
        {
            Enumeration<?>  e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            buf.append("BER Set");
            buf.append(nl);

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof ASN1Primitive)
                {
                    _dumpAsString(tab, verbose, (ASN1Primitive)o, buf);
                }
                else
                {
                    _dumpAsString(tab, verbose, ((ASN1Encodable)o).toASN1Primitive(), buf);
                }
            }
        }
        else if (obj instanceof ASN1Set)
        {
            Enumeration<?>  e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            buf.append("DER Set");
            buf.append(nl);

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof ASN1Primitive)
                {
                    _dumpAsString(tab, verbose, (ASN1Primitive)o, buf);
                }
                else
                {
                    _dumpAsString(tab, verbose, ((ASN1Encodable)o).toASN1Primitive(), buf);
                }
            }
        }
        else if (obj instanceof ASN1ObjectIdentifier)
        {
            try {
                String description = resolver.lookup((ASN1ObjectIdentifier) obj);
                buf.append(indent + "ObjectIdentifier(" + description + ")" + nl);
            } catch (IOException e) {
                buf.append(indent + "ObjectIdentifier(" + ((ASN1ObjectIdentifier) obj).getId() + ")" + nl);
            }
        }
        else if (obj instanceof ASN1Boolean)
        {
            buf.append(indent + "Boolean(" + ((ASN1Boolean)obj).isTrue() + ")" + nl);
        }
        else if (obj instanceof ASN1Integer)
        {
            buf.append(indent + "Integer(" + ((ASN1Integer)obj).getValue() + ")" + nl);
        }
        else if (obj instanceof DEROctetString)
        {
            ASN1OctetString oct = (ASN1OctetString)obj;
            buf.append(indent + "DER Octet String" + "[" + oct.getOctets().length + "] ");
            if (verbose)
            {
                buf.append(dumpBinaryDataAsString(indent, oct.getOctets()));
            }
            else{
                buf.append(nl);
            }
        }
        else if (obj instanceof DERBitString)
        {
            DERBitString bt = (DERBitString)obj;
            buf.append(indent + "DER Bit String" + "[" + bt.getBytes().length + ", " + bt.getPadBits() + "] ");
            if (verbose)
            {
                buf.append(dumpBinaryDataAsString(indent, bt.getBytes()));
            }
            else{
                buf.append(nl);
            }
        }
        else if (obj instanceof DERIA5String)
        {
            buf.append(indent + "IA5String(" + ((DERIA5String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERUTF8String)
        {
            buf.append(indent + "UTF8String(" + ((DERUTF8String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERPrintableString)
        {
            buf.append(indent + "PrintableString(" + ((DERPrintableString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERVisibleString)
        {
            buf.append(indent + "VisibleString(" + ((DERVisibleString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERBMPString)
        {
            buf.append(indent + "BMPString(" + ((DERBMPString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERT61String)
        {
            buf.append(indent + "T61String(" + ((DERT61String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1UTCTime)
        {
            buf.append(indent + "UTCTime(" + ((ASN1UTCTime)obj).getTime() + ") " + nl);
        }
        else if (obj instanceof DERGeneralizedTime)
        {
            buf.append(indent + "GeneralizedTime(" + ((DERGeneralizedTime)obj).getTime() + ") " + nl);
        }
        else if (obj instanceof BERApplicationSpecific)
        {
            buf.append(outputApplicationSpecific("BER", indent, verbose, obj, nl));
        }
        else if (obj instanceof DERApplicationSpecific)
        {
            buf.append(outputApplicationSpecific("DER", indent, verbose, obj, nl));
        }
        else if (obj instanceof ASN1Enumerated)
        {
            ASN1Enumerated en = (ASN1Enumerated) obj;
            buf.append(indent + "DER Enumerated(" + en.getValue() + ")" + nl);
        }
        else if (obj instanceof DERExternal)
        {
            DERExternal ext = (DERExternal) obj;
            buf.append(indent + "External " + nl);
            String          tab = indent + TAB;
            if (ext.getDirectReference() != null)
            {
                buf.append(tab + "Direct Reference: " + ext.getDirectReference().getId() + nl);
            }
            if (ext.getIndirectReference() != null)
            {
                buf.append(tab + "Indirect Reference: " + ext.getIndirectReference().toString() + nl);
            }
            if (ext.getDataValueDescriptor() != null)
            {
                _dumpAsString(tab, verbose, ext.getDataValueDescriptor(), buf);
            }
            buf.append(tab + "Encoding: " + ext.getEncoding() + nl);
            _dumpAsString(tab, verbose, ext.getExternalContent(), buf);
        }
        else
        {
            System.out.println("unknown type: " + obj.getClass().getName());
            buf.append(indent + obj.toString() + nl);
        }
    }
    
    private static String outputApplicationSpecific(String type, String indent, boolean verbose, ASN1Primitive obj, String nl)
    {
        DERApplicationSpecific app = (DERApplicationSpecific)obj;
        StringBuilder buf = new StringBuilder();

        if (app.isConstructed())
        {
            try
            {
                ASN1Sequence s = ASN1Sequence.getInstance(app.getObject(BERTags.SEQUENCE));
                buf.append(indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "]" + nl);
                for (Enumeration<ASN1Primitive> e = s.getObjects(); e.hasMoreElements();)
                {
                    _dumpAsString(indent + TAB, verbose, e.nextElement(), buf);
                }
            }
            catch (IOException e)
            {
                buf.append(e);
            }
            return buf.toString();
        }

        return indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "] (" + new String(Hex.encode(app.getContents())) + ")" + nl;
    }

    /**
     * Dump out the object as a string.
     *
     * @param obj  the object to be dumped
     * @param verbose  if true, dump out the contents of octet and bit strings.
     * @return  the resulting string.
     */
    public static String dumpAsString(Object   obj, boolean  verbose)
    {
        StringBuilder buf = new StringBuilder();

        if (obj instanceof ASN1Primitive)
        {
            _dumpAsString("", verbose, (ASN1Primitive)obj, buf);
        }
        else if (obj instanceof ASN1Encodable)
        {
            _dumpAsString("", verbose, ((ASN1Encodable)obj).toASN1Primitive(), buf);
        }
        else
        {
            return "unknown object type " + obj.toString();
        }

        return buf.toString();
    }

    private static String dumpBinaryDataAsString(String indent, byte[] bytes)
    {
        String nl = System.getProperty("line.separator");
        StringBuilder buf = new StringBuilder();

        indent += TAB;
        
        buf.append(nl);
        for (int i = 0; i < bytes.length; i += SAMPLE_SIZE)
        {
            if (bytes.length - i > SAMPLE_SIZE)
            {
                buf.append(indent);
                buf.append(new String(Hex.encode(bytes, i, SAMPLE_SIZE)));
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, SAMPLE_SIZE));
                buf.append(nl);
            }
            else
            {
                buf.append(indent);
                buf.append(new String(Hex.encode(bytes, i, bytes.length - i)));
                for (int j = bytes.length - i; j != SAMPLE_SIZE; j++)
                {
                    buf.append("  ");
                }
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, bytes.length - i));
                buf.append(nl);
            }
        }
        
        return buf.toString();
    }

    private static String calculateAscString(byte[] bytes, int off, int len)
    {
        StringBuilder buf = new StringBuilder();

        for (int i = off; i != off + len; i++)
        {
            if (bytes[i] >= ' ' && bytes[i] <= '~')
            {
                buf.append((char)bytes[i]);
            }
        }

        return buf.toString();
    }
}
