package com.clearfolio.viewer.controller;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

import org.springframework.web.multipart.MultipartFile;

/**
 * In-memory {@link MultipartFile} implementation backed by a byte array.
 */
public final class InMemoryMultipartFile implements MultipartFile {

    private final String name;
    private final String originalFilename;
    private final String contentType;
    private final byte[] content;

    /**
     * Creates a multipart file adapter from in-memory bytes.
     *
     * @param name multipart field name
     * @param originalFilename original uploaded filename
     * @param contentType uploaded content type
     * @param content file bytes
     */
    public InMemoryMultipartFile(
            String name,
            String originalFilename,
            String contentType,
            byte[] content) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.originalFilename = originalFilename;
        this.contentType = contentType;
        this.content = content == null ? new byte[0] : Arrays.copyOf(content, content.length);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getOriginalFilename() {
        return originalFilename;
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public boolean isEmpty() {
        return content.length == 0;
    }

    @Override
    public long getSize() {
        return content.length;
    }

    @Override
    public byte[] getBytes() {
        return Arrays.copyOf(content, content.length);
    }

    @Override
    public InputStream getInputStream() {
        return new ByteArrayInputStream(content);
    }

    @Override
    public void transferTo(File dest) throws IOException {
        transferTo(dest.toPath());
    }

    @Override
    public void transferTo(Path dest) throws IOException {
        Files.write(dest, content);
    }
}
